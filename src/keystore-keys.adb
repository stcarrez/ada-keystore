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
--  | Wallet key count | 4b
--  | PAD 0            | 4b
--  +------------------+
--  | Key type         | 4b
--  | Key size         | 4b
--  | Counter for key  | 4b
--  | Counter for iv   | 4b
--  | Salt for key     | 32b
--  | Salt for iv      | 32b
--  | Key slot sign    | 32b
--  | Dir key # 1      | 32b ---
--  | Dir iv # 1       | 32b  ^
--  | Dir sign # 1     | 32b  |
--  | Entry key # 1    | 32b  |
--  | Entry iv # 1     | 32b  | Encrypted by user's password
--  | Entry sign #1    | 32b  |
--  | Data key # 1     | 32b  |
--  | Data iv # 1      | 32b  v
--  | Data sign #1     | 32b ---
--  | Key HMAC-256     | 32b
--  | PAD 0 / Random   | 80b
--  +------------------+
--  | Key slot #2      | 512b
--  +------------------+
--  | Key slot #3      | 512b
--  +------------------+
--  | Key slot #4      | 512b
--  +------------------+
--  | Key slot #5      | 512b
--  +------------------+
--  | Key slot #6      | 512b
--  +------------------+
--  | Key slot #7      | 512b
--  +------------------+
--  | PAD 0 / Random   |
--  +------------------+

package body Keystore.Keys is

   use Interfaces;
   use Ada.Streams;
   use Util.Encoders.KDF;

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Keystore.Keys");

   procedure Save_Key (Manager  : in out Key_Manager;
                       Buffer   : in out IO.Marshaller;
                       Password : in Secret_Key;
                       Slot     : in Key_Slot;
                       Config   : in Wallet_Config;
                       Stream   : in out IO.Wallet_Stream'Class);

   procedure Extract (Buffer   : in out IO.Marshaller;
                      Lock_Key : in Secret_Key;
                      Lock_IV  : in Secret_Key;
                      Crypt    : in out Cryptor;
                      Hmac     : in out Util.Encoders.HMAC.SHA256.Context);

   function Verify (Manager  : in Key_Manager;
                    Buffer   : in out IO.Marshaller;
                    Password : in Secret_Key;
                    Size     : in Positive;
                    Config   : in out Wallet_Config) return Boolean;

   procedure Generate (Manager : in out Key_Manager;
                       Crypt   : in out Cryptor);

   procedure Save (Buffer   : in out IO.Marshaller;
                   Lock_Key : in Secret_Key;
                   Lock_IV  : in Secret_Key;
                   Crypt    : in Cryptor;
                   Hmac     : in out Util.Encoders.HMAC.SHA256.Context);

   --  ------------------------------
   --  Set the IV vector to be used for the encryption and decruption of the given block number.
   --  ------------------------------
   procedure Set_IV (Into  : in out Cryptor;
                     Block : in IO.Block_Number) is
      Block_IV : constant Util.Encoders.AES.Word_Block_Type
      := (others => Interfaces.Unsigned_32 (Block));
   begin
      Into.Decipher.Set_IV (Into.IV, Block_IV);
      Into.Cipher.Set_IV (Into.IV, Block_IV);
   end Set_IV;

   --  ------------------------------
   --  Extract the AES encryption key, the AES IV and the signature key.
   --  Update the HMAC with the extracted encryption keys for global verification.
   --  ------------------------------
   procedure Extract (Buffer   : in out IO.Marshaller;
                      Lock_Key : in Secret_Key;
                      Lock_IV  : in Secret_Key;
                      Crypt    : in out Cryptor;
                      Hmac     : in out Util.Encoders.HMAC.SHA256.Context) is
   begin
      IO.Get_Secret (Buffer, Crypt.Key, Lock_Key, Lock_IV);
      IO.Get_Secret (Buffer, Crypt.IV, Lock_Key, Lock_IV);
      IO.Get_Secret (Buffer, Crypt.Sign, Lock_Key, Lock_IV);
      Util.Encoders.HMAC.SHA256.Update (Hmac, Crypt.Key);
      Util.Encoders.HMAC.SHA256.Update (Hmac, Crypt.IV);
      Util.Encoders.HMAC.SHA256.Update (Hmac, Crypt.Sign);

      Crypt.Cipher.Set_Key (Crypt.Key, Util.Encoders.AES.CBC);
      Crypt.Cipher.Set_Padding (Util.Encoders.AES.NO_PADDING);
      Crypt.Decipher.Set_Key (Crypt.Key, Util.Encoders.AES.CBC);
      Crypt.Decipher.Set_Padding (Util.Encoders.AES.NO_PADDING);
   end Extract;

   procedure Generate (Manager : in out Key_Manager;
                       Crypt   : in out Cryptor) is
   begin
      Manager.Random.Generate (Crypt.Sign);
      Manager.Random.Generate (Crypt.Key);
      Manager.Random.Generate (Crypt.IV);

      Crypt.Cipher.Set_Key (Crypt.Key, Util.Encoders.AES.CBC);
      Crypt.Cipher.Set_Padding (Util.Encoders.AES.NO_PADDING);
      Crypt.Decipher.Set_Key (Crypt.Key, Util.Encoders.AES.CBC);
      Crypt.Decipher.Set_Padding (Util.Encoders.AES.NO_PADDING);
   end Generate;

   procedure Save (Buffer   : in out IO.Marshaller;
                   Lock_Key : in Secret_Key;
                   Lock_IV  : in Secret_Key;
                   Crypt    : in Cryptor;
                   Hmac     : in out Util.Encoders.HMAC.SHA256.Context) is
   begin
      IO.Put_Secret (Buffer, Crypt.Key, Lock_Key, Lock_IV);
      IO.Put_Secret (Buffer, Crypt.IV, Lock_Key, Lock_IV);
      IO.Put_Secret (Buffer, Crypt.Sign, Lock_Key, Lock_IV);
      Util.Encoders.HMAC.SHA256.Update (Hmac, Crypt.Key);
      Util.Encoders.HMAC.SHA256.Update (Hmac, Crypt.IV);
      Util.Encoders.HMAC.SHA256.Update (Hmac, Crypt.Sign);
   end Save;

   function Verify (Manager  : in Key_Manager;
                    Buffer   : in out IO.Marshaller;
                    Password : in Secret_Key;
                    Size     : in Positive;
                    Config   : in out Wallet_Config) return Boolean is
      Salt_Key      : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      Salt_IV       : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      Sign          : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      Lock_Key      : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      Lock_IV       : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      Result        : Util.Encoders.SHA256.Hash_Array;
      Hmac          : Util.Encoders.HMAC.SHA256.Context;
      Counter_Key   : Interfaces.Unsigned_32;
      Counter_IV    : Interfaces.Unsigned_32;
   begin
      Counter_Key := IO.Get_Unsigned_32 (Buffer);
      Counter_IV := IO.Get_Unsigned_32 (Buffer);
      if Counter_Key = 0 or Counter_IV = 0 or Size /= Util.Encoders.AES.AES_256_Length then
         return False;
      end if;

      IO.Get_Secret (Buffer, Salt_Key, Manager.Crypt.Key, Manager.Crypt.IV);
      IO.Get_Secret (Buffer, Salt_IV, Manager.Crypt.Key, Manager.Crypt.IV);
      IO.Get_Secret (Buffer, Sign, Manager.Crypt.Key, Manager.Crypt.IV);

      --  Generate a derived key from the password, salt, counter.
      PBKDF2_HMAC_SHA256 (Password => Password,
                          Salt     => Salt_IV,
                          Counter  => Positive (Counter_IV),
                          Result   => Lock_IV);

      PBKDF2_HMAC_SHA256 (Password => Lock_IV,
                          Salt     => Salt_Key,
                          Counter  => Positive (Counter_Key),
                          Result   => Lock_Key);

      --  Build a signature from the master key and the wallet salt.
      Util.Encoders.HMAC.SHA256.Set_Key (Hmac, Sign);

      --  Get the directory encryption key and IV.
      Extract (Buffer, Lock_Key, Lock_IV, Config.Dir, Hmac);
      Extract (Buffer, Lock_Key, Lock_IV, Config.Data, Hmac);
      Extract (Buffer, Lock_Key, Lock_IV, Config.Key, Hmac);

      Util.Encoders.HMAC.SHA256.Finish (Hmac, Result);

      return Result = Buffer.Data (Buffer.Pos .. Buffer.Pos + Result'Length - 1);
   end Verify;

   --  ------------------------------
   --  Save the wallet config encryption keys in the key slot and protect that
   --  key using the user's password.  New salts and counters are generated and
   --  the user's password is passed through PBKDF2 to get the encryption key
   --  that protects the key slot.
   --  ------------------------------
   procedure Save_Key (Manager  : in out Key_Manager;
                       Buffer   : in out IO.Marshaller;
                       Password : in Secret_Key;
                       Slot     : in Key_Slot;
                       Config   : in Wallet_Config;
                       Stream   : in out IO.Wallet_Stream'Class) is

      Salt_Key    : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      Salt_IV     : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      Sign        : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      Lock_Key    : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      Lock_IV     : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      Counter_Key : Positive;
      Counter_IV  : Positive;
      Hmac        : Util.Encoders.HMAC.SHA256.Context;
      Result      : Util.Encoders.SHA256.Hash_Array;
   begin
      --  Make a first random counter in range 100_000 .. 1_148_575.
      Counter_Key := Natural (Manager.Random.Generate mod Config.Max_Counter);
      if Counter_Key < Positive (Config.Min_Counter) then
         Counter_Key := Positive (Config.Min_Counter);
      end if;

      --  Make a second random counter in range 100_000 .. 372_140.
      Counter_IV := Natural (Manager.Random.Generate mod Config.Max_Counter);
      if Counter_IV < Positive (Config.Min_Counter) then
         Counter_IV := Positive (Config.Min_Counter);
      end if;

      Manager.Random.Generate (Salt_Key);
      Manager.Random.Generate (Salt_IV);
      Manager.Random.Generate (Sign);

      Buffer.Pos := WH_KEY_LIST_START + IO.Block_Index (Slot) * WH_SLOT_SIZE - WH_SLOT_SIZE;
      Buffer.Data (Buffer.Pos .. Buffer.Pos + WH_KEY_SIZE - 1) := (others => 0);
      IO.Put_Unsigned_32 (Buffer, WH_KEY_PBKDF2);
      IO.Put_Unsigned_32 (Buffer, Interfaces.Unsigned_32 (Lock_Key.Length));
      IO.Put_Unsigned_32 (Buffer, Interfaces.Unsigned_32 (Counter_Key));
      IO.Put_Unsigned_32 (Buffer, Interfaces.Unsigned_32 (Counter_IV));
      IO.Put_Secret (Buffer, Salt_Key, Manager.Crypt.Key, Manager.Crypt.IV);
      IO.Put_Secret (Buffer, Salt_IV, Manager.Crypt.Key, Manager.Crypt.IV);
      IO.Put_Secret (Buffer, Sign, Manager.Crypt.Key, Manager.Crypt.IV);

      --  Generate a derived key from the password, salt, counter.
      PBKDF2_HMAC_SHA256 (Password => Password,
                          Salt     => Salt_IV,
                          Counter  => Counter_IV,
                          Result   => Lock_IV);

      PBKDF2_HMAC_SHA256 (Password => Lock_IV,
                          Salt     => Salt_Key,
                          Counter  => Counter_Key,
                          Result   => Lock_Key);

      --  Build a signature from the lock key.
      Util.Encoders.HMAC.SHA256.Set_Key (Hmac, Sign);

      Save (Buffer, Lock_Key, Lock_IV, Config.Dir, Hmac);
      Save (Buffer, Lock_Key, Lock_IV, Config.Data, Hmac);
      Save (Buffer, Lock_Key, Lock_IV, Config.Key, Hmac);

      Util.Encoders.HMAC.SHA256.Finish (Hmac, Result);
      Buffer.Data (Buffer.Pos .. Buffer.Pos + Result'Length - 1) := Result;

      Stream.Write (Block  => Manager.Header_Block,
                    Cipher => Manager.Crypt.Cipher,
                    Sign   => Manager.Crypt.Sign,
                    From   => Buffer);
   end Save_Key;

   --  Open the key manager and read the wallet header block.  Use the secret key
   --  to decrypt/encrypt the wallet header block.
   procedure Open (Manager  : in out Key_Manager;
                   Password : in Secret_Key;
                   Ident    : in Wallet_Identifier;
                   Block    : in Keystore.IO.Block_Number;
                   Root     : out Keystore.IO.Block_Number;
                   Config   : in out Wallet_Config;
                   Stream   : in out IO.Wallet_Stream'Class) is

      Value   : Interfaces.Unsigned_32;
      Size    : IO.Block_Index;
      Buffer  : IO.Marshaller;
   begin
      Manager.Header_Block := Block;
      Stream.Read (Block        => Manager.Header_Block,
                   Decipher     => Manager.Crypt.Decipher,
                   Sign         => Manager.Crypt.Sign,
                   Decrypt_Size => Size,
                   Into         => Buffer);
      if IO.Get_Unsigned_16 (Buffer) /= IO.BT_WALLET_HEADER then
         Keystore.Logs.Warn (Log, "Invalid wallet block header BN{0}", Manager.Header_Block);
         raise Invalid_Block;
      end if;
      IO.Skip (Buffer, 2);
      Value := IO.Get_Unsigned_32 (Buffer);
      IO.Skip (Buffer, 8);
      if IO.Get_Unsigned_32 (Buffer) /= WH_MAGIC then
         Keystore.Logs.Warn (Log, "Invalid wallet magic in header BN{0}", Manager.Header_Block);
         raise Invalid_Block;
      end if;
      Value := IO.Get_Unsigned_32 (Buffer);
      if Value /= 1 then
         Log.Warn ("Version{0} not supported in header BN{0}",
                   Interfaces.Unsigned_32'Image (Value),
                   IO.Block_Number'Image (Manager.Header_Block));
         raise Invalid_Block;
      end if;
      Value := IO.Get_Unsigned_32 (Buffer);
      if Value /= Interfaces.Unsigned_32 (Ident) then
         Log.Warn ("Wallet id{0} does not match in header BN{0}",
                   Interfaces.Unsigned_32'Image (Value),
                   IO.Block_Number'Image (Manager.Header_Block));
         raise Invalid_Block;
      end if;
      Value := IO.Get_Unsigned_32 (Buffer);
      if Value = 0 then
         Log.Warn ("Wallet block{0} is invalid in header BN{0}",
                   Interfaces.Unsigned_32'Image (Value),
                   IO.Block_Number'Image (Manager.Header_Block));
         raise Invalid_Block;
      end if;
      Root := IO.Block_Number (Value);

      for Slot in 1 .. 7 loop
         Buffer.Pos := WH_KEY_LIST_START + IO.Block_Index (Slot) * WH_SLOT_SIZE - WH_SLOT_SIZE;
         Value := IO.Get_Unsigned_32 (Buffer);
         if Value = WH_KEY_PBKDF2 then
            Value := IO.Get_Unsigned_32 (Buffer);
            if Value > 0 and Value <= WH_KEY_SIZE then
               if Verify (Manager, Buffer, Password, Positive (Value), Config) then
                  return;
               end if;
            end if;
         end if;
      end loop;
      Keystore.Logs.Info (Log, "No password match for wallet block{0}", Manager.Header_Block);
      raise Bad_Password;
   end Open;

   procedure Create (Manager  : in out Key_Manager;
                     Password : in Secret_Key;
                     Slot     : in Key_Slot;
                     Ident    : in Wallet_Identifier;
                     Block    : in Keystore.IO.Block_Number;
                     Root     : in Keystore.IO.Block_Number;
                     Config   : in out Wallet_Config;
                     Stream   : in out IO.Wallet_Stream'Class) is
      Buffer   : IO.Marshaller;
   begin
      Generate (Manager, Config.Data);
      Generate (Manager, Config.Dir);
      Generate (Manager, Config.Key);
      Manager.Header_Block := Block;

      --  Build wallet header.
      Buffer.Data := (others => 0);
      Buffer.Block := Block;
      IO.Set_Header (Into => Buffer,
                     Tag  => IO.BT_WALLET_HEADER,
                     Id   => Interfaces.Unsigned_32 (Ident));
      IO.Put_Unsigned_32 (Buffer, WH_MAGIC);
      IO.Put_Unsigned_32 (Buffer, 1);
      IO.Put_Unsigned_32 (Buffer, Interfaces.Unsigned_32 (Ident));
      IO.Put_Unsigned_32 (Buffer, Interfaces.Unsigned_32 (Root));

      Save_Key (Manager, Buffer, Password, Slot, Config, Stream);
   end Create;

   procedure Set_Header_Key (Manager : in out Key_Manager;
                             Key     : in Secret_Key) is
      Header_Key : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
   begin
      --  Build the header key by deriving the key we get.
      --  Generate a master key from the random, salt, counter.
      PBKDF2_HMAC_SHA256 (Password => Key,
                          Salt     => Key,
                          Counter  => 1234,
                          Result   => Header_Key);

      Manager.Crypt.Decipher.Set_Key (Header_Key, Util.Encoders.AES.CBC);
      Manager.Crypt.Decipher.Set_Padding (Util.Encoders.AES.NO_PADDING);
      Manager.Crypt.Cipher.Set_Key (Header_Key, Util.Encoders.AES.CBC);
      Manager.Crypt.Cipher.Set_Padding (Util.Encoders.AES.NO_PADDING);
   end Set_Header_Key;

   procedure Set_Key (Manager  : in out Key_Manager;
                      Password : in Secret_Key;
                      Slot     : in Key_Slot;
                      Stream   : in out IO.Wallet_Stream'Class) is
      Size     : IO.Block_Index;
      Buffer   : IO.Marshaller;
      Config   : Wallet_Config;
   begin
      Stream.Read (Block        => Manager.Header_Block,
                   Decipher     => Manager.Crypt.Decipher,
                   Sign         => Manager.Crypt.Sign,
                   Decrypt_Size => Size,
                   Into         => Buffer);
      if IO.Get_Unsigned_32 (Buffer) /= IO.BT_WALLET_HEADER then
         Log.Warn ("Invalid wallet block header BN{0}",
                   IO.Block_Number'Image (Manager.Header_Block));
         raise Invalid_Block;
      end if;

      Save_Key (Manager, Buffer, Password, Slot, Config, Stream);
   end Set_Key;

end Keystore.Keys;
