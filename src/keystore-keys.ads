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
with Util.Encoders.SHA256;
with Keystore.IO;
with Keystore.Random;
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
      Data        : Cryptor;
      Dir         : Cryptor;
      Key         : Cryptor;
      Max_Counter : Interfaces.Unsigned_32 := 300_000;
      Min_Counter : Interfaces.Unsigned_32 := 100_000;
   end record;

   type Key_Manager is limited private;

   --  Open the key manager and read the wallet header block.  Use the secret key
   --  to decrypt/encrypt the wallet header block.
   procedure Open (Manager  : in out Key_Manager;
                   Password : in Secret_Key;
                   Ident    : in Wallet_Identifier;
                   Block    : in Keystore.IO.Storage_Block;
                   Root     : out Keystore.IO.Storage_Block;
                   Config   : in out Wallet_Config;
                   Stream   : in out IO.Wallet_Stream'Class);

   --  Open the key manager and read the wallet header block.  Use the secret key
   --  to decrypt/encrypt the wallet header block.
   procedure Create (Manager  : in out Key_Manager;
                     Password : in Secret_Key;
                     Slot     : in Key_Slot;
                     Ident    : in Wallet_Identifier;
                     Block    : in Keystore.IO.Storage_Block;
                     Root     : in Keystore.IO.Storage_Block;
                     Config   : in out Wallet_Config;
                     Stream   : in out IO.Wallet_Stream'Class);

   procedure Set_Header_Key (Manager  : in out Key_Manager;
                             Key      : in Secret_Key);

   procedure Set_Key (Manager      : in out Key_Manager;
                      Password     : in Secret_Key;
                      New_Password : in Secret_Key;
                      Config       : in Keystore.Wallet_Config;
                      Mode         : in Mode_Type;
                      Ident        : in Wallet_Identifier;
                      Block        : in Keystore.IO.Storage_Block;
                      Stream       : in out IO.Wallet_Stream'Class);

private

   --  Size of a key slot.
   WH_SLOT_SIZE     : constant := 512;

   --  Wallet header magic.
   WH_MAGIC          : constant := 16#Ada00Ada#;

   WH_HEADER_SIZE    : constant := 16;
   WH_HASH_SIZE      : constant := Util.Encoders.SHA256.HASH_SIZE;
   WH_SALT_SIZE      : constant := 32;
   WH_KEY_SIZE       : constant := Util.Encoders.AES.AES_256_Length;

   WH_HEADER_START   : constant IO.Block_Index := IO.BT_DATA_START;
   WH_HEADER_LENGTH  : constant := 16 + 16 + 8;
   WH_KEY_LIST_START : constant IO.Block_Index := WH_HEADER_START + WH_HEADER_LENGTH + 1;

   --  Key slot type is using PBKDF2-HMAC-256.
   WH_KEY_PBKDF2     : constant := 16#0001#;

   type Key_Manager is limited record
      Id                : Wallet_Identifier;
      Parent_Id         : Wallet_Identifier;
      Header_Block      : Keystore.IO.Storage_Block;
      Random            : Keystore.Random.Generator;
      Crypt             : Cryptor;
   end record;

end Keystore.Keys;
