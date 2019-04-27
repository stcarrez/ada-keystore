-----------------------------------------------------------------------
--  keystore-keys -- Keystore key management
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--
--  Licensed under the Apache License, Version 2.0 (the "License");
--  you may not use this file except in compliance with the License.
--  You may obtain a copy of the License at
--
--      http://www.apache.org/licenses/LICENSE-2.0
--
--  Unless required by applicable law or agreed to in writing, software
--  distributed under the License is distributed on an "AS IS" BASIS,
--  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
--  See the License for the specific language governing permissions and
--  limitations under the License.
-----------------------------------------------------------------------
with Ada.Streams;
with Interfaces;
with Util.Log.Loggers;
with Util.Encoders.HMAC.SHA256;
with Util.Encoders.KDF.PBKDF2_HMAC_SHA256;
with Keystore.Logs;

--  Wallet header encrypted with the parent wallet id
--  +------------------+
--  | Block HMAC-256   | 32b
--  +------------------+
--  | 01 01            | 2b
--  | Encrypt size     | 2b
--  | Parent Wallet id | 4b
--  | PAD 0            | 4b
--  | PAD 0            | 4b
--  +------------------+
--  | Wallet magic     | 4b
--  | Wallet version   | 4b
--  | Wallet id        | 4b
--  | Wallet block ID  | 4b
--  +------------------+
--  | Key HMAC-256     | 32b
--  | Wallet salt      | 32b
--  | Wallet key count | 4b
--  | PAD 0            | 4b
--  +------------------+
--  | Key type         | 4b
--  | Key size         | 4b
--  | Key counter      | 4b
--  | PAD 0            | 4b
--  | Wallet key # 1   | 32b
--  | Wallet iv # 1    | 32b
--  +------------------+
--  | Key type         | 4b
--  | Key size         | 4b
--  | Key counter      | 4b
--  | PAD 0            | 4b
--  | Wallet key # 2   | 32b
--  | Wallet iv # 2    | 32b
--  +------------------+
--  | Key type         | 4b
--  | Key size         | 4b
--  | Key counter      | 4b
--  | PAD 0            | 4b
--  | Wallet key # 3   | 32b
--  | Wallet iv # 3    | 32b
--  +------------------+
--  | Key type         | 4b
--  | Key size         | 4b
--  | Key counter      | 4b
--  | PAD 0            | 4b
--  | Wallet key # 4   | 32b
--  | Wallet iv # 4    | 32b
--  +------------------+

package body Keystore.Keys is

   use type Interfaces.Unsigned_16;
   use type Interfaces.Unsigned_32;
   use Ada.Streams;
   use Util.Encoders.KDF;

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Keystore.Keys");

   protected body Key_Manager is

      procedure Verify (Password : in Secret_Key;
                        Size     : in Positive;
                        Counter  : in Positive;
                        Protect_Key : out Secret_Key;
                        IV       : out Util.Encoders.AES.Word_Block_Type;
                        Cipher   : in out Util.Encoders.AES.Encoder;
                        Decipher : in out Util.Encoders.AES.Decoder) is
         Salt          : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
         Lock_Key      : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
         Master_Key    : Secret_Key (Length => Stream_Element_Offset (Size));
         Result        : Util.Encoders.SHA256.Hash_Array;
      begin
         Util.Encoders.Create (Buffer.Data (WH_SALT_START .. WH_SALT_END), Salt);

         --  Generate a derived key from the password, salt, counter.
         PBKDF2_HMAC_SHA256 (Password => Password,
                             Salt     => Salt,
                             Counter  => Counter,
                             Result   => Lock_Key);
         IO.Get_Secret (Buffer, Master_Key, Lock_Key);

         --  Build a signature from the master key and the wallet salt.
         Util.Encoders.HMAC.SHA256.Sign (Key    => Master_Key,
                                         Data   => Buffer.Data (WH_SALT_START .. WH_SALT_END),
                                         Result => Result);

         if Result = Buffer.Data (WH_KEY_HASH_START .. WH_KEY_HASH_END) then
            --  success, Master_Key is ready
            IO.Get_Data (Buffer, IV);
            Cipher.Set_Key (Master_Key, Util.Encoders.AES.CBC);
            Cipher.Set_Padding (Util.Encoders.AES.NO_PADDING);
            Decipher.Set_Key (Master_Key, Util.Encoders.AES.CBC);
            Decipher.Set_Padding (Util.Encoders.AES.NO_PADDING);

            --  Generate the protect key from the master key and salt.
            --  The protect key is just a curiosity for IO.Put_Secret to be able to
            --  put a key in the IO buffer because the Secret_Key type is private
            --  and does not give access to the key content: we can only access it through
            --  Encrypt_Secret operation.  We don't want to share the Master_Key and it
            --  must be common to all password slot.
            PBKDF2_HMAC_SHA256 (Password => Master_Key,
                                Salt     => Salt,
                                Counter  => 3,
                                Result   => Protect_Key);
            return;
         end if;

      end Verify;

      procedure Save_Key (Password : in Secret_Key;
                          Slot     : in Key_Slot;
                          Salt     : in Secret_Key;
                          IV       : in Util.Encoders.AES.Word_Block_Type;
                          Stream   : in out IO.Wallet_Stream'Class) is
         Protect_Key : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
         Counter     : constant Positive := 20000;
      begin
         Buffer.Pos := WH_KEY_LIST_START + IO.Block_Index (Slot) * WH_SLOT_SIZE - WH_SLOT_SIZE;
         Buffer.Data (Buffer.Pos .. Buffer.Pos + WH_KEY_SIZE - 1) := (others => 0);
         IO.Put_Unsigned_32 (Buffer, WH_KEY_PBKDF2);
         IO.Put_Unsigned_32 (Buffer, Interfaces.Unsigned_32 (Master_Key.Length));
         IO.Put_Unsigned_32 (Buffer, Interfaces.Unsigned_32 (Counter));
         IO.Put_Unsigned_32 (Buffer, 0);

         --  Generate a derived key from the password, salt, counter.
         PBKDF2_HMAC_SHA256 (Password => Password,
                             Salt     => Salt,
                             Counter  => Counter,
                             Result   => Protect_Key);
         IO.Put_Secret (Buffer, Master_Key, Protect_Key);
         IO.Put_Data (Buffer, IV);

         Stream.Write (Block  => Header_Block,
                       Cipher => Header_Cipher,
                       Sign   => Sign,
                       From   => Buffer);
      end Save_Key;

      --  Open the key manager and read the wallet header block.  Use the secret key
      --  to decrypt/encrypt the wallet header block.
      procedure Open (Password : in Secret_Key;
                      Ident    : in Wallet_Identifier;
                      Block    : in Keystore.IO.Block_Number;
                      Root     : out Keystore.IO.Block_Number;
                      Protect_Key : out Secret_Key;
                      IV       : out Util.Encoders.AES.Word_Block_Type;
                      Cipher   : in out Util.Encoders.AES.Encoder;
                      Decipher : in out Util.Encoders.AES.Decoder;
                      Stream   : in out IO.Wallet_Stream'Class) is

         Value   : Interfaces.Unsigned_32;
         Counter : Interfaces.Unsigned_32;
         Size    : IO.Block_Index;
      begin
         Header_Block := Block;
         Stream.Read (Block        => Header_Block,
                      Decipher     => Header_Decipher,
                      Sign         => Sign,
                      Decrypt_Size => Size,
                      Into         => Buffer);
         if IO.Get_Unsigned_16 (Buffer) /= IO.BT_WALLET_HEADER then
            Keystore.Logs.Warn (Log, "Invalid wallet block header BN{0}", Header_Block);
            raise Invalid_Block;
         end if;
         IO.Skip (Buffer, 2);
         Value := IO.Get_Unsigned_32 (Buffer);
         IO.Skip (Buffer, 8);
         if IO.Get_Unsigned_32 (Buffer) /= WH_MAGIC then
            Keystore.Logs.Warn (Log, "Invalid wallet magic in header BN{0}", Header_Block);
            raise Invalid_Block;
         end if;
         Value := IO.Get_Unsigned_32 (Buffer);
         if Value /= 1 then
            Log.Warn ("Version{0} not supported in header BN{0}",
                      Interfaces.Unsigned_32'Image (Value),
                      IO.Block_Number'Image (Header_Block));
            raise Invalid_Block;
         end if;
         Value := IO.Get_Unsigned_32 (Buffer);
         if Value /= Interfaces.Unsigned_32 (Ident) then
            Log.Warn ("Wallet id{0} does not match in header BN{0}",
                      Interfaces.Unsigned_32'Image (Value),
                      IO.Block_Number'Image (Header_Block));
            raise Invalid_Block;
         end if;
         Value := IO.Get_Unsigned_32 (Buffer);
         if Value = 0 then
            Log.Warn ("Wallet block{0} is invalid in header BN{0}",
                      Interfaces.Unsigned_32'Image (Value),
                      IO.Block_Number'Image (Header_Block));
            raise Invalid_Block;
         end if;
         Root := IO.Block_Number (Value);

         for Slot in 1 .. 7 loop
            Buffer.Pos := WH_KEY_LIST_START + IO.Block_Index (Slot) * WH_SLOT_SIZE - WH_SLOT_SIZE;
            Value := IO.Get_Unsigned_32 (Buffer);
            if Value = WH_KEY_PBKDF2 then
               Value := IO.Get_Unsigned_32 (Buffer);
               Counter := IO.Get_Unsigned_32 (Buffer);
               if Value > 0 and Value <= WH_KEY_SIZE and Counter > 0 then
                  IO.Skip (Buffer, 4);
                  Verify (Password, Positive (Value), Positive (Counter),
                          Protect_Key, IV, Cipher, Decipher);
                  if Cipher.Has_Key and Decipher.Has_Key then
                     return;
                  end if;
               end if;
            end if;
         end loop;
         Keystore.Logs.Info (Log, "No password match for wallet block{0}", Header_Block);
         raise Bad_Password;
      end Open;

      procedure Create (Password : in Secret_Key;
                        Slot     : in Key_Slot;
                        Ident    : in Wallet_Identifier;
                        Block    : in Keystore.IO.Block_Number;
                        Root     : in Keystore.IO.Block_Number;
                        Protect_Key : out Secret_Key;
                        IV       : out Util.Encoders.AES.Word_Block_Type;
                        Cipher   : in out Util.Encoders.AES.Encoder;
                        Decipher : in out Util.Encoders.AES.Decoder;
                        Stream   : in out IO.Wallet_Stream'Class) is
         use Interfaces;

         Tmp_Rand : Ada.Streams.Stream_Element_Array (1 .. 32);
         Salt     : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
         Counter  : Positive;
         Pos      : Ada.Streams.Stream_Element_Offset;
      begin
         Header_Block := Block;
         Random.Generate (Tmp_Rand);
         Util.Encoders.Create (Tmp_Rand, Salt);

         Random.Generate (Tmp_Rand);

         --  Make a random counter in range 100_000 .. 372_140.
         Counter := 100_000 + Natural (Shift_Left (Interfaces.Unsigned_32 (Tmp_Rand (11)), 10))
         + Natural (Shift_Left (Interfaces.Unsigned_32 (Tmp_Rand (23)), 2));

         --  Generate a master key from the random, salt, counter.
         PBKDF2_HMAC_SHA256 (Password => Password,
                             Salt     => Salt,
                             Counter  => Counter,
                             Result   => Master_Key);

         Cipher.Set_Key (Master_Key);
         Cipher.Set_Padding (Util.Encoders.AES.NO_PADDING);
         Decipher.Set_Key (Master_Key);
         Decipher.Set_Padding (Util.Encoders.AES.NO_PADDING);

         --  Build wallet header.
         Buffer.Data := (others => 0);
         IO.Set_Header (Into => Buffer,
                        Tag  => IO.BT_WALLET_HEADER,
                        Id   => Interfaces.Unsigned_32 (Ident));
         IO.Put_Unsigned_32 (Buffer, WH_MAGIC);
         IO.Put_Unsigned_32 (Buffer, 1);
         IO.Put_Unsigned_32 (Buffer, Interfaces.Unsigned_32 (Ident));
         IO.Put_Unsigned_32 (Buffer, Interfaces.Unsigned_32 (Root));
         Random.Generate (Buffer.Data (WH_SALT_START .. WH_SALT_END));
         Util.Encoders.Create (Buffer.Data (WH_SALT_START .. WH_SALT_END), Salt);

         --  Build the master key signature from the master key and the wallet salt.
         Util.Encoders.HMAC.SHA256.Sign (Key    => Master_Key,
                                         Data   => Buffer.Data (WH_SALT_START .. WH_SALT_END),
                                         Result => Buffer.Data (WH_KEY_HASH_START .. WH_KEY_HASH_END));

         PBKDF2_HMAC_SHA256 (Password => Master_Key,
                             Salt     => Salt,
                             Counter  => 3,
                             Result   => Protect_Key);

         Random.Generate (Tmp_Rand);
         Pos := 1;
         for I in IV'Range loop
            IV (I) := Shift_Left (Unsigned_32 (Tmp_Rand (Pos)), 24) or
              Shift_Left (Unsigned_32 (Tmp_Rand (Pos + 1)), 16) or
              Shift_Left (Unsigned_32 (Tmp_Rand (Pos + 2)), 8) or
              Unsigned_32 (Tmp_Rand (Pos + 3));
            Pos := Pos + 4;
         end loop;
         Save_Key (Password, Slot, Salt, IV, Stream);
      end Create;

      procedure Set_Header_Key (Key : in Secret_Key) is
         Header_Key : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      begin
         --  Build the header key by deriving the key we get.
         --  Generate a master key from the random, salt, counter.
         PBKDF2_HMAC_SHA256 (Password => Key,
                             Salt     => Key,
                             Counter  => 1234,
                             Result   => Header_Key);

         Header_Decipher.Set_Key (Header_Key, Util.Encoders.AES.CBC);
         Header_Decipher.Set_Padding (Util.Encoders.AES.NO_PADDING);
         Header_Cipher.Set_Key (Header_Key, Util.Encoders.AES.CBC);
         Header_Cipher.Set_Padding (Util.Encoders.AES.NO_PADDING);
      end Set_Header_Key;

      procedure Set_Key (Password : in Secret_Key;
                         Slot     : in Key_Slot;
                         Stream   : in out IO.Wallet_Stream'Class) is
         Salt     : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
         IV       : Util.Encoders.AES.Word_Block_Type;
         Size     : IO.Block_Index;
      begin
         Stream.Read (Block        => Header_Block,
                      Decipher     => Header_Decipher,
                      Sign         => Sign,
                      Decrypt_Size => Size,
                      Into         => Buffer);
         if IO.Get_Unsigned_32 (Buffer) /= IO.BT_WALLET_HEADER then
            Log.Warn ("Invalid wallet block header BN{0}",
                      IO.Block_Number'Image (Header_Block));
            raise Invalid_Block;
         end if;
         Util.Encoders.Create (Buffer.Data (WH_SALT_START .. WH_SALT_END), Salt);

         Save_Key (Password, Slot, Salt, IV, Stream);
      end Set_Key;

   end Key_Manager;

end Keystore.Keys;
