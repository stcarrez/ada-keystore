-----------------------------------------------------------------------
--  keystore-io -- IO low level operation for the keystore
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
with Util.Encoders.AES;
with Keystore.Buffers;
with Keystore.Marshallers;
private package Keystore.IO is

   use Ada.Streams;

   --  Data block size defined to a 4K to map system page.
   Block_Size           : constant := Buffers.Block_Size;

   BT_HMAC_HEADER_SIZE  : constant := 32;
   BT_TYPE_HEADER_SIZE  : constant := 16;

   --  Block type magic values.
   BT_WALLET_UNUSED     : constant := 16#0000#;
   BT_WALLET_HEADER     : constant := 16#0101#;
   BT_WALLET_DIRECTORY  : constant := 16#0202#;
   BT_WALLET_DATA       : constant := 16#0303#;

   SIZE_U16             : constant := 2;
   SIZE_U32             : constant := 4;
   SIZE_U64             : constant := 8;
   SIZE_DATE            : constant := SIZE_U64;
   SIZE_HMAC            : constant := BT_HMAC_HEADER_SIZE;
   SIZE_KIND            : constant := SIZE_U32;
   SIZE_BLOCK           : constant := SIZE_U32;
   SIZE_SECRET          : constant := 32;
   SIZE_IV              : constant := 16;

   type Block_Kind is (MASTER_BLOCK, DIRECTORY_BLOCK, DATA_BLOCK);

   subtype Buffer_Size is Buffers.Buffer_Size;
   subtype Block_Index is Buffers.Block_Index;
   subtype Block_Type is Buffers.Block_Type;
   subtype IO_Block_Type is Buffers.IO_Block_Type;
   subtype Block_Count is Buffers.Block_Count;
   subtype Block_Number is Buffers.Block_Number;
   subtype Storage_Block is Buffers.Storage_Block;
   subtype Storage_Identifier is Buffers.Storage_Identifier;

   subtype Marshaller is Marshallers.Marshaller;

   BT_HEADER_START    : constant Block_Index := Block_Index'First;
   BT_DATA_START      : constant Block_Index := BT_HEADER_START + BT_TYPE_HEADER_SIZE;
   BT_DATA_LENGTH     : constant Block_Index := Block_Index'Last - BT_DATA_START + 1;
   BT_HMAC_HEADER_POS : constant Stream_Element_Offset := Block_Index'Last + 1;

   HEADER_BLOCK_NUM   : constant Block_Number := 1;

   DEFAULT_STORAGE_ID : constant Storage_Identifier := 0;

   type Wallet_Stream is limited interface;
   type Wallet_Stream_Access is access all Wallet_Stream'Class;

   --  Returns true if the block number is allocated.
   function Is_Used (Stream  : in out Wallet_Stream;
                     Block   : in Storage_Block) return Boolean is abstract;

   --  Read from the wallet stream the block identified by the number and
   --  call the `Process` procedure with the data block content.
   procedure Read (Stream  : in out Wallet_Stream;
                   Block   : in Storage_Block;
                   Process : not null access
                     procedure (Data : in IO_Block_Type)) is abstract;

   --  Write in the wallet stream the block identified by the block number.
   procedure Write (Stream  : in out Wallet_Stream;
                    Block   : in Storage_Block;
                    Process : not null access
                      procedure (Data : out IO_Block_Type)) is abstract;

   --  Allocate a new block and return the block number in `Block`.
   procedure Allocate (Stream  : in out Wallet_Stream;
                       Kind    : in Block_Kind;
                       Block   : out Storage_Block) is abstract;

   --  Release the block number.
   procedure Release (Stream  : in out Wallet_Stream;
                      Block   : in Storage_Block) is abstract;

   --  Close the wallet stream and release any resource.
   procedure Close (Stream : in out Wallet_Stream) is abstract;

   --  Set some header data in the keystore file.
   procedure Set_Header_Data (Stream : in out Wallet_Stream;
                              Index  : in Header_Slot_Index_Type;
                              Kind   : in Header_Slot_Type;
                              Data   : in Ada.Streams.Stream_Element_Array) is abstract;

   --  Get the header data information from the keystore file.
   procedure Get_Header_Data (Stream : in out Wallet_Stream;
                              Index  : in Header_Slot_Index_Type;
                              Kind   : out Header_Slot_Type;
                              Data   : out Ada.Streams.Stream_Element_Array;
                              Last   : out Ada.Streams.Stream_Element_Offset) is abstract;

   --  Read the block from the wallet IO stream and decrypt the block content using
   --  the decipher object.  The decrypted content is stored in the marshaller which
   --  is ready to read the start of the block header.
   procedure Read (Stream       : in out Wallet_Stream'Class;
                   Decipher     : in out Util.Encoders.AES.Decoder;
                   Sign         : in Secret_Key;
                   Decrypt_Size : out Block_Index;
                   Into         : in out Buffers.Storage_Buffer);

   --  Write the block in the wallet IO stream.  Encrypt the block data using the
   --  cipher object.  Sign the header and encrypted data using HMAC-256 and the
   --  given signature.
   procedure Write (Stream       : in out Wallet_Stream'Class;
                    Encrypt_Size : in Block_Index := BT_DATA_LENGTH;
                    Cipher       : in out Util.Encoders.AES.Encoder;
                    Sign         : in Secret_Key;
                    From         : in out Buffers.Storage_Buffer) with
     Pre => Encrypt_Size mod 16 = 0 and Encrypt_Size <= BT_DATA_LENGTH;

end Keystore.IO;
