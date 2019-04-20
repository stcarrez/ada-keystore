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
with Util.Encoders.AES;
with Util.Encoders.SHA256;
with Keystore.IO;
with Keystore.Random;
private package Keystore.Keys is

   use type IO.Block_Index;

   --  Size of a key slot.
   WH_SLOT_SIZE     : constant := 256;

   --  Wallet header magic.
   WH_MAGIC          : constant := 16#Ada00Ada#;

   WH_HEADER_SIZE    : constant := 16;
   WH_HASH_SIZE      : constant := Util.Encoders.SHA256.HASH_SIZE;
   WH_SALT_SIZE      : constant := 32;
   WH_KEY_SIZE       : constant := Util.Encoders.AES.AES_256_Length;

   WH_HEADER_START   : constant IO.Block_Index := IO.BT_DATA_START;
   WH_KEY_HASH_START : constant IO.Block_Index := WH_HEADER_START + WH_HEADER_SIZE;
   WH_KEY_HASH_END   : constant IO.Block_Index := WH_KEY_HASH_START + WH_HASH_SIZE - 1;
   WH_SALT_START     : constant IO.Block_Index := WH_KEY_HASH_END + 1;
   WH_SALT_END       : constant IO.Block_Index := WH_SALT_START + WH_SALT_SIZE - 1;
   WH_KEY_LIST_START : constant IO.Block_Index := WH_SALT_END + 8 + 1;

   WH_KEY_PBKDF2     : constant := 16#0001#;

   protected type Key_Manager is

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
                      Stream   : in out IO.Wallet_Stream'Class);

      procedure Set_Header_Key (Key : in Secret_Key);

      procedure Set_Key (Password : in Secret_Key;
                         Slot     : in Key_Slot;
                         Stream   : in out IO.Wallet_Stream'Class);

      --  Open the key manager and read the wallet header block.  Use the secret key
      --  to decrypt/encrypt the wallet header block.
      procedure Create (Password : in Secret_Key;
                        Slot     : in Key_Slot;
                        Ident    : in Wallet_Identifier;
                        Block    : in Keystore.IO.Block_Number;
                        Root     : in Keystore.IO.Block_Number;
                        Protect_Key : out Secret_Key;
                        IV       : out Util.Encoders.AES.Word_Block_Type;
                        Cipher   : in out Util.Encoders.AES.Encoder;
                        Decipher : in out Util.Encoders.AES.Decoder;
                        Stream   : in out IO.Wallet_Stream'Class);

   private
      Id                : Wallet_Identifier;
      Parent_Id         : Wallet_Identifier;
      Header_Block      : Keystore.IO.Block_Number;
      Master_Key        : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      Header_Decipher   : Util.Encoders.AES.Decoder;
      Header_Cipher     : Util.Encoders.AES.Encoder;
      Sign              : Util.Encoders.SHA256.Hash_Array := (others => 0);
      Buffer            : Keystore.IO.Marshaller;
      Random            : Keystore.Random.Generator;
   end Key_Manager;

end Keystore.Keys;
