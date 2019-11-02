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
with Util.Encoders.SHA256;
with Util.Encoders.HMAC.SHA256;
with Util.Encoders.KDF.PBKDF2_HMAC_SHA256;
with Keystore.Logs;
with Keystore.Buffers;

--  === Master keys ===
--  Wallet header encrypted with the parent wallet id
--
--  ```
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
--  | Wallet lid       | 4b
--  | Wallet block ID  | 4b
--  +------------------+
--  | Wallet gid       | 16b
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
--  | Data key # 1     | 32b  |
--  | Data iv # 1      | 32b  | Encrypted by user's password
--  | Data sign #1     | 32b  |
--  | Key key # 1      | 32b  |
--  | Key iv # 1       | 32b  v
--  | Key sign #1      | 32b ---
--  | Slot HMAC-256    | 32b
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
--  ```
--
package body Keystore.Keys is

   use Interfaces;
   use Ada.Streams;
   use Util.Encoders.KDF;

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Keystore.Keys");

   procedure Save_Key (Manager  : in out Key_Manager;
                       Buffer   : in out Marshallers.Marshaller;
                       Password : in out Keystore.Passwords.Provider'Class;
                       Slot     : in Key_Slot;
                       Config   : in Wallet_Config;
                       Stream   : in out IO.Wallet_Stream'Class);

   procedure Erase_Key (Manager  : in out Key_Manager;
                        Buffer   : in out Marshallers.Marshaller;
                        Slot     : in Key_Slot;
                        Stream   : in out IO.Wallet_Stream'Class);

   procedure Extract (Buffer   : in out Marshallers.Marshaller;
                      Lock_Key : in Secret_Key;
                      Lock_IV  : in Secret_Key;
                      Crypt    : in out Cryptor;
                      Hmac     : in out Util.Encoders.HMAC.SHA256.Context);

   function Verify (Manager  : in Key_Manager;
                    Buffer   : in out Marshallers.Marshaller;
                    Password : in Passwords.Provider'Class;
                    Size     : in Positive;
                    Config   : in out Wallet_Config) return Boolean;

   procedure Generate (Manager : in out Key_Manager;
                       Crypt   : in out Cryptor);

   procedure Save (Buffer   : in out IO.Marshaller;
                   Lock_Key : in Secret_Key;
                   Lock_IV  : in Secret_Key;
                   Crypt    : in Cryptor;
                   Hmac     : in out Util.Encoders.HMAC.SHA256.Context);

   procedure Load (Manager  : in out Key_Manager;
                   Block    : in Keystore.IO.Storage_Block;
                   Ident    : in Wallet_Identifier;
                   Buffer   : in out IO.Marshaller;
                   Root     : out Keystore.IO.Storage_Block;
                   UUID     : out UUID_Type;
                   Stream   : in out IO.Wallet_Stream'Class);

   --  ------------------------------
   --  Set the IV vector to be used for the encryption and decryption of the given block number.
   --  ------------------------------
   procedure Set_IV (Into  : in out Cryptor;
                     Block : in IO.Block_Number) is
      Block_IV : constant Util.Encoders.AES.Word_Block_Type
      := (others => Interfaces.Unsigned_32 (Block));
   begin
      Into.Decipher.Set_IV (Into.IV, Block_IV);
      Into.Cipher.Set_IV (Into.IV, Block_IV);
   end Set_IV;

   procedure Set_Key (Into : in out Cryptor;
                      From : in Cryptor) is
   begin
      Into.Cipher.Set_Key (From.Key, Util.Encoders.AES.CBC);
      Into.Cipher.Set_Padding (Util.Encoders.AES.NO_PADDING);
      Into.Decipher.Set_Key (From.Key, Util.Encoders.AES.CBC);
      Into.Decipher.Set_Padding (Util.Encoders.AES.NO_PADDING);
   end Set_Key;

   --  ------------------------------
   --  Extract the AES encryption key, the AES IV and the signature key.
   --  Update the HMAC with the extracted encryption keys for global verification.
   --  ------------------------------
   procedure Extract (Buffer   : in out Marshallers.Marshaller;
                      Lock_Key : in Secret_Key;
                      Lock_IV  : in Secret_Key;
                      Crypt    : in out Cryptor;
                      Hmac     : in out Util.Encoders.HMAC.SHA256.Context) is
   begin
      Marshallers.Get_Secret (Buffer, Crypt.Key, Lock_Key, Lock_IV);
      Marshallers.Get_Secret (Buffer, Crypt.IV, Lock_Key, Lock_IV);
      Marshallers.Get_Secret (Buffer, Crypt.Sign, Lock_Key, Lock_IV);
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

   procedure Save (Buffer   : in out Marshallers.Marshaller;
                   Lock_Key : in Secret_Key;
                   Lock_IV  : in Secret_Key;
                   Crypt    : in Cryptor;
                   Hmac     : in out Util.Encoders.HMAC.SHA256.Context) is
   begin
      Marshallers.Put_Secret (Buffer, Crypt.Key, Lock_Key, Lock_IV);
      Marshallers.Put_Secret (Buffer, Crypt.IV, Lock_Key, Lock_IV);
      Marshallers.Put_Secret (Buffer, Crypt.Sign, Lock_Key, Lock_IV);
      Util.Encoders.HMAC.SHA256.Update (Hmac, Crypt.Key);
      Util.Encoders.HMAC.SHA256.Update (Hmac, Crypt.IV);
      Util.Encoders.HMAC.SHA256.Update (Hmac, Crypt.Sign);
   end Save;

   function Verify (Manager  : in Key_Manager;
                    Buffer   : in out Marshallers.Marshaller;
                    Password : in Passwords.Provider'Class;
                    Size     : in Positive;
                    Config   : in out Wallet_Config) return Boolean is
      procedure Get_Password (Secret : in Secret_Key);

      Buf           : constant Buffers.Buffer_Accessor := Buffer.Buffer.Data.Value;
      Salt_Key      : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      Salt_IV       : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      Sign          : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      Lock_Key      : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      Lock_IV       : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      Result        : Util.Encoders.SHA256.Hash_Array;
      Hmac          : Util.Encoders.HMAC.SHA256.Context;
      Counter_Key   : Interfaces.Unsigned_32;
      Counter_IV    : Interfaces.Unsigned_32;

      --  Generate a derived key from the password, salt, counter.
      procedure Get_Password (Secret : in Secret_Key) is
      begin
         PBKDF2_HMAC_SHA256 (Password => Secret,
                             Salt     => Salt_IV,
                             Counter  => Positive (Counter_IV),
                             Result   => Lock_IV);
      end Get_Password;

   begin
      Counter_Key := Marshallers.Get_Unsigned_32 (Buffer);
      Counter_IV := Marshallers.Get_Unsigned_32 (Buffer);
      if Counter_Key = 0 or Counter_IV = 0 or Size /= Util.Encoders.AES.AES_256_Length then
         return False;
      end if;

      Marshallers.Get_Secret (Buffer, Salt_Key, Manager.Crypt.Key, Manager.Crypt.IV);
      Marshallers.Get_Secret (Buffer, Salt_IV, Manager.Crypt.Key, Manager.Crypt.IV);
      Marshallers.Get_Secret (Buffer, Sign, Manager.Crypt.Key, Manager.Crypt.IV);

      Password.Get_Password (Get_Password'Access);
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

      return Result = Buf.Data (Buffer.Pos + 1 .. Buffer.Pos + Result'Length);
   end Verify;

   --  ------------------------------
   --  Save the wallet config encryption keys in the key slot and protect that
   --  key using the user's password.  New salts and counters are generated and
   --  the user's password is passed through PBKDF2 to get the encryption key
   --  that protects the key slot.
   --  ------------------------------
   procedure Save_Key (Manager  : in out Key_Manager;
                       Buffer   : in out Marshallers.Marshaller;
                       Password : in out Keystore.Passwords.Provider'Class;
                       Slot     : in Key_Slot;
                       Config   : in Wallet_Config;
                       Stream   : in out IO.Wallet_Stream'Class) is
      procedure Get_Password (Secret : in Secret_Key);

      Salt_Key    : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      Salt_IV     : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      Sign        : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      Lock_Key    : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      Lock_IV     : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      Counter_Key : Positive;
      Counter_IV  : Positive;
      Hmac        : Util.Encoders.HMAC.SHA256.Context;
      Result      : Util.Encoders.SHA256.Hash_Array;
      Buf         : constant Buffers.Buffer_Accessor := Buffer.Buffer.Data.Value;

      --  Generate a derived key from the password, salt, counter.
      procedure Get_Password (Secret : in Secret_Key) is
      begin
         PBKDF2_HMAC_SHA256 (Password => Secret,
                             Salt     => Salt_IV,
                             Counter  => Counter_IV,
                             Result   => Lock_IV);
      end Get_Password;

   begin
      Log.Info ("Saving key for wallet {0}", To_String (Config.UUID));

      --  Make a first random counter in range 100_000 .. 1_148_575.
      Counter_Key := 1 + Natural (Manager.Random.Generate mod Config.Max_Counter);
      if Counter_Key < Positive (Config.Min_Counter) then
         Counter_Key := Positive (Config.Min_Counter);
      end if;

      --  Make a second random counter in range 100_000 .. 372_140.
      Counter_IV := 1 + Natural (Manager.Random.Generate mod Config.Max_Counter);
      if Counter_IV < Positive (Config.Min_Counter) then
         Counter_IV := Positive (Config.Min_Counter);
      end if;

      Manager.Random.Generate (Salt_Key);
      Manager.Random.Generate (Salt_IV);
      Manager.Random.Generate (Sign);

      Buffer.Pos := Key_Position (Slot);
      Buf.Data (Buffer.Pos + 1 .. Buffer.Pos + WH_KEY_SIZE) := (others => 0);
      if Password in Passwords.Slot_Provider'Class then
         Marshallers.Put_Unsigned_32 (Buffer, WH_KEY_GPG2);
      else
         Marshallers.Put_Unsigned_32 (Buffer, WH_KEY_PBKDF2);
      end if;
      Marshallers.Put_Unsigned_32 (Buffer, Interfaces.Unsigned_32 (Lock_Key.Length));
      Marshallers.Put_Unsigned_32 (Buffer, Interfaces.Unsigned_32 (Counter_Key));
      Marshallers.Put_Unsigned_32 (Buffer, Interfaces.Unsigned_32 (Counter_IV));
      Marshallers.Put_Secret (Buffer, Salt_Key, Manager.Crypt.Key, Manager.Crypt.IV);
      Marshallers.Put_Secret (Buffer, Salt_IV, Manager.Crypt.Key, Manager.Crypt.IV);
      Marshallers.Put_Secret (Buffer, Sign, Manager.Crypt.Key, Manager.Crypt.IV);

      Password.Get_Password (Get_Password'Access);
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
      Buf.Data (Buffer.Pos + 1 .. Buffer.Pos + Result'Length) := Result;

      Stream.Write (Cipher  => Manager.Crypt.Cipher,
                    Sign    => Manager.Crypt.Sign,
                    From    => Buffer.Buffer);
   end Save_Key;

   --  ------------------------------
   --  Erase the walley key slot amd save the waller master block.
   --  ------------------------------
   procedure Erase_Key (Manager  : in out Key_Manager;
                        Buffer   : in out Marshallers.Marshaller;
                        Slot     : in Key_Slot;
                        Stream   : in out IO.Wallet_Stream'Class) is
      Buf : constant Buffers.Buffer_Accessor := Buffer.Buffer.Data.Value;
   begin
      Buffer.Pos := Key_Position (Slot);
      Buf.Data (Buffer.Pos + 1 .. Buffer.Pos + WH_KEY_SIZE) := (others => 0);

      Stream.Write (Cipher  => Manager.Crypt.Cipher,
                    Sign    => Manager.Crypt.Sign,
                    From    => Buffer.Buffer);
   end Erase_Key;

   --  ------------------------------
   --  Load the wallet header keys
   --  ------------------------------
   procedure Load (Manager  : in out Key_Manager;
                   Block    : in Keystore.IO.Storage_Block;
                   Ident    : in Wallet_Identifier;
                   Buffer   : in out IO.Marshaller;
                   Root     : out Keystore.IO.Storage_Block;
                   UUID     : out UUID_Type;
                   Stream   : in out IO.Wallet_Stream'Class) is
      Value   : Interfaces.Unsigned_32;
      Size    : IO.Block_Index;
   begin
      Buffer.Buffer := Buffers.Allocate (Block);
      Manager.Header_Block := Block;
      Stream.Read (Decipher     => Manager.Crypt.Decipher,
                   Sign         => Manager.Crypt.Sign,
                   Decrypt_Size => Size,
                   Into         => Buffer.Buffer);
      Buffer.Pos := IO.BT_HEADER_START - 1;
      if Marshallers.Get_Unsigned_16 (Buffer) /= IO.BT_WALLET_HEADER then
         Keystore.Logs.Warn (Log, "Invalid wallet block header BN{0}", Manager.Header_Block);
         raise Invalid_Block;
      end if;
      Marshallers.Skip (Buffer, 2);
      Value := Marshallers.Get_Unsigned_32 (Buffer);
      Marshallers.Skip (Buffer, 8);
      if Marshallers.Get_Unsigned_32 (Buffer) /= WH_MAGIC then
         Keystore.Logs.Warn (Log, "Invalid wallet magic in header BN{0}", Manager.Header_Block);
         raise Invalid_Block;
      end if;
      Value := Marshallers.Get_Unsigned_32 (Buffer);
      if Value /= 1 then
         Log.Warn ("Version{0} not supported in header BN{0}",
                   Interfaces.Unsigned_32'Image (Value),
                   IO.Block_Number'Image (Manager.Header_Block.Block));
         raise Invalid_Block;
      end if;
      Value := Marshallers.Get_Unsigned_32 (Buffer);
      if Value /= Interfaces.Unsigned_32 (Ident) then
         Log.Warn ("Wallet id{0} does not match in header BN{0}",
                   Interfaces.Unsigned_32'Image (Value),
                   IO.Block_Number'Image (Manager.Header_Block.Block));
         raise Invalid_Block;
      end if;
      Value := Marshallers.Get_Unsigned_32 (Buffer);
      if Value = 0 then
         Log.Warn ("Wallet block{0} is invalid in header BN{0}",
                   Interfaces.Unsigned_32'Image (Value),
                   IO.Block_Number'Image (Manager.Header_Block.Block));
         raise Invalid_Block;
      end if;
      Root.Storage := Block.Storage;
      Root.Block := IO.Block_Number (Value);

      --  Extract wallet uuid.
      Marshallers.Get_UUID (Buffer, UUID);
   end Load;

   --  Open the key manager and read the wallet header block.  Use the secret key
   --  to decrypt/encrypt the wallet header block.
   procedure Open (Manager  : in out Key_Manager;
                   Password : in out Keystore.Passwords.Provider'Class;
                   Ident    : in Wallet_Identifier;
                   Block    : in Keystore.IO.Storage_Block;
                   Root     : out Keystore.IO.Storage_Block;
                   Config   : in out Wallet_Config;
                   Process  : access procedure (Buffer : in out Marshallers.Marshaller;
                                                Slot   : in Key_Slot);
                   Stream   : in out IO.Wallet_Stream'Class) is

      Value   : Interfaces.Unsigned_32;
      Buffer  : Marshallers.Marshaller;
   begin
      Load (Manager, Block, Ident, Buffer, Root, Config.UUID, Stream);

      --  See which key slot is used.
      for Slot in Key_Slot'Range loop
         Buffer.Pos := Key_Position (Slot);
         Value := Marshallers.Get_Unsigned_32 (Buffer);
         Config.Keys (Slot) := Value /= 0;
      end loop;

      if Password in Keystore.Passwords.Slot_Provider'Class then
         while Passwords.Slot_Provider'Class (Password).Has_Password loop
            declare
               Slot : constant Key_Slot
                 := Passwords.Slot_Provider'Class (Password).Get_Key_Slot;
            begin
               Buffer.Pos := Key_Position (Slot);
               Value := Marshallers.Get_Unsigned_32 (Buffer);
               if Value = WH_KEY_GPG2 then
                  Value := Marshallers.Get_Unsigned_32 (Buffer);
                  if Value > 0 and Value <= WH_KEY_SIZE then
                     if Verify (Manager, Buffer, Password, Positive (Value), Config) then
                        Config.Slot := Slot;
                        if Process /= null then
                           Process (Buffer, Slot);
                        end if;
                        return;
                     end if;
                  end if;
               end if;
            end;
            Passwords.Slot_Provider'Class (Password).Next;
         end loop;
      else
         for Slot in Key_Slot'Range loop
            Buffer.Pos := Key_Position (Slot);
            Value := Marshallers.Get_Unsigned_32 (Buffer);
            if Value = WH_KEY_PBKDF2 then
               Value := Marshallers.Get_Unsigned_32 (Buffer);
               if Value > 0 and Value <= WH_KEY_SIZE then
                  if Verify (Manager, Buffer, Password, Positive (Value), Config) then
                     Config.Slot := Slot;
                     if Process /= null then
                        Process (Buffer, Slot);
                     end if;
                     return;
                  end if;
               end if;
            end if;
         end loop;
      end if;

      Keystore.Logs.Info (Log, "No password match for wallet block{0}", Manager.Header_Block);
      raise Bad_Password;
   end Open;

   procedure Create (Manager  : in out Key_Manager;
                     Password : in out Keystore.Passwords.Provider'Class;
                     Slot     : in Key_Slot;
                     Ident    : in Wallet_Identifier;
                     Block    : in Keystore.IO.Storage_Block;
                     Root     : in Keystore.IO.Storage_Block;
                     Config   : in out Wallet_Config;
                     Stream   : in out IO.Wallet_Stream'Class) is
      Buffer   : IO.Marshaller;
   begin
      Buffer.Buffer := Buffers.Allocate (Block);
      Generate (Manager, Config.Data);
      Generate (Manager, Config.Dir);
      Generate (Manager, Config.Key);
      Manager.Random.Generate (Config.UUID);
      Manager.Header_Block := Block;

      --  Build wallet header.
      Buffer.Buffer.Data.Value.Data := (others => 0);
      Marshallers.Set_Header (Into => Buffer,
                              Tag  => IO.BT_WALLET_HEADER,
                              Id   => Ident);
      Marshallers.Put_Unsigned_32 (Buffer, WH_MAGIC);
      Marshallers.Put_Unsigned_32 (Buffer, 1);
      Marshallers.Put_Unsigned_32 (Buffer, Interfaces.Unsigned_32 (Ident));
      Marshallers.Put_Unsigned_32 (Buffer, Interfaces.Unsigned_32 (Root.Block));

      --  Write wallet uuid.
      Marshallers.Put_UUID (Buffer, Config.UUID);

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

   procedure Set_Key (Manager      : in out Key_Manager;
                      Password     : in out Keystore.Passwords.Provider'Class;
                      New_Password : in out Keystore.Passwords.Provider'Class;
                      Config       : in Keystore.Wallet_Config;
                      Mode         : in Mode_Type;
                      Ident        : in Wallet_Identifier;
                      Block        : in Keystore.IO.Storage_Block;
                      Stream       : in out IO.Wallet_Stream'Class) is

      procedure Process (Buffer : in out Marshallers.Marshaller;
                         Slot   : in Key_Slot);

      Local_Config : Wallet_Config;
      Root         : Keystore.IO.Storage_Block;

      procedure Process (Buffer : in out Marshallers.Marshaller;
                         Slot   : in Key_Slot) is
         function Find_Free_Slot return Key_Slot;

         function Find_Free_Slot return Key_Slot is
            Value : Interfaces.Unsigned_32;
         begin
            for Slot in Key_Slot'Range loop
               Buffer.Pos := Key_Position (Slot);
               Value := Marshallers.Get_Unsigned_32 (Buffer);
               if Value = 0 then
                  return Slot;
               end if;
            end loop;
            Log.Info ("No available free slot to add a new key");
            raise No_Key_Slot;
         end Find_Free_Slot;

      begin
         Local_Config.Min_Counter := Unsigned_32 (Config.Min_Counter);
         Local_Config.Max_Counter := Unsigned_32 (Config.Max_Counter);
         case Mode is
            when KEY_ADD =>
               Save_Key (Manager, Buffer, New_Password, Find_Free_Slot,
                         Local_Config, Stream);

            when KEY_REPLACE =>
               Save_Key (Manager, Buffer, New_Password, Slot, Local_Config, Stream);

            when KEY_REMOVE =>
               Erase_Key (Manager, Buffer, Slot, Stream);

            when KEY_REMOVE_LAST =>
               Erase_Key (Manager, Buffer, Slot, Stream);

         end case;
      end Process;

   begin
      Open (Manager, Password, Ident, Block, Root, Local_Config,
            Process'Access, Stream);
   end Set_Key;

   --  ------------------------------
   --  Remove the key from the key slot identified by `Slot`.  The password is necessary to
   --  make sure a valid password is available.  The `Remove_Current` must be set to remove
   --  the slot when it corresponds to the used password.
   --  ------------------------------
   procedure Remove_Key (Manager        : in out Key_Manager;
                         Password       : in out Keystore.Passwords.Provider'Class;
                         Slot           : in Key_Slot;
                         Remove_Current : in Boolean;
                         Ident          : in Wallet_Identifier;
                         Block          : in Keystore.IO.Storage_Block;
                         Stream         : in out IO.Wallet_Stream'Class) is

      procedure Process (Buffer : in out Marshallers.Marshaller;
                         Password_Slot   : in Key_Slot);

      procedure Process (Buffer : in out Marshallers.Marshaller;
                         Password_Slot   : in Key_Slot) is
      begin
         if Slot /= Password_Slot or Remove_Current then
            Erase_Key (Manager, Buffer, Slot, Stream);
         else
            Log.Info ("Refusing to delete key slot used by current password");
            raise Used_Key_Slot;
         end if;
      end Process;

      Local_Config : Wallet_Config;
      Root         : Keystore.IO.Storage_Block;
   begin
      Open (Manager, Password, Ident, Block, Root, Local_Config,
            Process'Access, Stream);
   end Remove_Key;

end Keystore.Keys;
