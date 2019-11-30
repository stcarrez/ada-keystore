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
with Interfaces;
with Util.Encoders.AES;
with Keystore.IO;
with Keystore.Random;
with Keystore.Passwords.Keys;
with Keystore.Marshallers;
private package Keystore.Keys is

   use type IO.Block_Index;

   type Cryptor is limited record
      Cipher    : Util.Encoders.AES.Encoder;
      Decipher  : Util.Encoders.AES.Decoder;
      Key       : Secret_Key (Length => 32);
      IV        : Secret_Key (Length => 16);
      Sign      : Secret_Key (Length => 32);
   end record;

   --  Set the IV vector to be used for the encryption and decryption of the given block number.
   procedure Set_IV (Into  : in out Cryptor;
                     Block : in IO.Block_Number);

   procedure Set_Key (Into : in out Cryptor;
                      From : in Cryptor);

   type Wallet_Config is limited record
      UUID        : UUID_Type;
      Keys        : Key_Slot_Allocation := (others => False);
      Slot        : Key_Slot;
      Data        : Cryptor;
      Dir         : Cryptor;
      Key         : Cryptor;
      Max_Counter : Interfaces.Unsigned_32 := 300_000;
      Min_Counter : Interfaces.Unsigned_32 := 100_000;
      Randomize   : Boolean;
   end record;

   type Key_Manager is limited private;

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
                   Stream   : in out IO.Wallet_Stream'Class);

   --  Create the wallet key block.
   procedure Create (Manager  : in out Key_Manager;
                     Password : in out Passwords.Provider'Class;
                     Slot     : in Key_Slot;
                     Ident    : in Wallet_Identifier;
                     Block    : in Keystore.IO.Storage_Block;
                     Root     : in Keystore.IO.Storage_Block;
                     Config   : in out Wallet_Config;
                     Stream   : in out IO.Wallet_Stream'Class);

   procedure Set_Header_Key (Manager  : in out Key_Manager;
                             Key      : in Secret_Key);

   --  Set a new key
   procedure Set_Key (Manager      : in out Key_Manager;
                      Password     : in out Keystore.Passwords.Provider'Class;
                      New_Password : in out Keystore.Passwords.Provider'Class;
                      Config       : in Keystore.Wallet_Config;
                      Mode         : in Mode_Type;
                      Ident        : in Wallet_Identifier;
                      Block        : in Keystore.IO.Storage_Block;
                      Stream       : in out IO.Wallet_Stream'Class);

   --  Remove the key from the key slot identified by `Slot`.  The password is necessary to
   --  make sure a valid password is available.  The `Remove_Current` must be set to remove
   --  the slot when it corresponds to the used password.
   procedure Remove_Key (Manager        : in out Key_Manager;
                         Password       : in out Keystore.Passwords.Provider'Class;
                         Slot           : in Key_Slot;
                         Remove_Current : in Boolean;
                         Ident          : in Wallet_Identifier;
                         Block          : in Keystore.IO.Storage_Block;
                         Stream         : in out IO.Wallet_Stream'Class);

   --  Create a new masker keys for a children wallet and save the new keys in the buffer.
   procedure Create_Master_Key (Manager : in out Key_Manager;
                                Buffer  : in out Marshallers.Marshaller;
                                Crypt   : in Cryptor);

   --  Extract from the buffer the master keys to open the children wallet.
   procedure Load_Master_Key (Manager : in out Key_Manager;
                              Buffer  : in out Marshallers.Marshaller;
                              Crypt   : in Cryptor);

   --  Set the master key by using the password provider.
   procedure Set_Master_Key (Manager  : in out Key_Manager;
                             Password : in out Keystore.Passwords.Keys.Key_Provider'Class);

private

   --  Size of a key slot.
   WH_SLOT_SIZE     : constant := 512;

   --  Wallet header magic.
   WH_MAGIC          : constant := 16#Ada00Ada#;

   WH_KEY_SIZE       : constant := Util.Encoders.AES.AES_256_Length;

   WH_HEADER_START   : constant IO.Block_Index := IO.BT_DATA_START;
   WH_HEADER_LENGTH  : constant := 16 + 16 + 8;
   WH_KEY_LIST_START : constant IO.Block_Index := WH_HEADER_START + WH_HEADER_LENGTH + 1;

   --  Key slot type is using PBKDF2-HMAC-256.
   WH_KEY_PBKDF2     : constant := 16#0001#;

   --  Key slot type is using PBKDF2-HMAC-256 with a GPG2 key.
   WH_KEY_GPG2       : constant := 16#0002#;

   type Key_Manager is limited record
      Id                : Wallet_Identifier;
      Parent_Id         : Wallet_Identifier;
      Header_Block      : Keystore.IO.Storage_Block;
      Random            : Keystore.Random.Generator;
      Crypt             : Cryptor;
   end record;

   function Key_Position (Slot : in Key_Slot) return IO.Block_Index is
      (WH_KEY_LIST_START + IO.Block_Index (Slot) * WH_SLOT_SIZE - WH_SLOT_SIZE - 1);

end Keystore.Keys;
