-----------------------------------------------------------------------
--  keystore-io-headers -- Keystore file header operations
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

with Util.Log.Loggers;
with Util.Encoders.HMAC.SHA256;
with Keystore.Marshallers;

--  === Header block ===
--  The first block of the file is the keystore header block which contains clear
--  information signed by an HMAC header.  The header block contains the keystore
--  UUID as well as a short description of each storage data file.  It also contains
--  some optional header data.
--
--  ```
--  +------------------+
--  | 41 64 61 00      | 4b = Ada
--  | 00 9A 72 57      | 4b = 10/12/1815
--  | 01 9D B1 AC      | 4b = 27/11/1852
--  | 00 01            | 2b = Version 1
--  | 00 01            | 2b = File header length in blocks
--  +------------------+
--  | Keystore UUID    | 16b
--  | Storage ID       | 4b
--  | Block size       | 4b
--  | Storage count    | 4b
--  | Header Data count| 2b
--  +------------------+-----
--  | Header Data size | 2b
--  | Header Data type | 2b = 0 (NONE), 1 (GPG1) 2, (GPG2)
--  +------------------+
--  | Header Data      | Nb
--  +------------------+-----
--  | ...              |
--  +------------------+-----
--  | 0                |
--  +------------------+-----
--  | ...              |
--  +------------------+-----
--  | Storage ID       | 4b
--  | Storage type     | 2b
--  | Storage status   | 2b  00 = open, Ada = sealed
--  | Storage max bloc | 4b
--  | Storage HMAC     | 32b = 44b
--  +------------------+----
--  | Header HMAC-256  | 32b
--  +------------------+----
--  ```
package body Keystore.IO.Headers is

   use type Interfaces.Unsigned_16;
   use type Interfaces.Unsigned_32;
   use type Keystore.Buffers.Storage_Identifier;

   --  Header magic numbers.
   MAGIC_1             : constant := 16#41646100#;
   MAGIC_2             : constant := 16#009A7257#;
   MAGIC_3             : constant := 16#019DB1AC#;
   VERSION_1           : constant := 1;

   --  Header positions and length.
   STORAGE_COUNT_POS   : constant := 1 + 16 + 16 + 4 + 4;
   HEADER_DATA_POS     : constant := STORAGE_COUNT_POS + 4;
   STORAGE_SLOT_LENGTH : constant := 4 + 2 + 2 + 4 + 32;

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Keystore.IO.Headers");

   function Get_Storage_Offset (Index : in Natural) return Block_Index is
      (Block_Index'Last - STORAGE_SLOT_LENGTH * Stream_Element_Offset (Index) - 1);

   function Get_Header_Data_Size (Header : in Wallet_Header) return Buffer_Size;

   procedure Seek_Header_Data (Buffer : in out Keystore.Marshallers.Marshaller;
                               Index  : in Header_Slot_Index_Type);

   --  ------------------------------
   --  Build a new header with the given UUID and for the storage.
   --  The header buffer is allocated and filled so that it can be written by Write_Header.
   --  ------------------------------
   procedure Build_Header (UUID    : in UUID_Type;
                           Storage : in Storage_Identifier;
                           Header  : in out Wallet_Header) is
      Buffer : Keystore.Marshallers.Marshaller;
   begin
      Header.Buffer := Buffers.Allocate ((Storage, HEADER_BLOCK_NUM));
      Buffer.Buffer := Header.Buffer;
      Marshallers.Set_Header (Buffer, MAGIC_1);
      Marshallers.Put_Unsigned_32 (Buffer, MAGIC_2);
      Marshallers.Put_Unsigned_32 (Buffer, MAGIC_3);
      Marshallers.Put_Unsigned_16 (Buffer, VERSION_1);
      Marshallers.Put_Unsigned_16 (Buffer, 1);
      Marshallers.Put_UUID (Buffer, UUID);
      Marshallers.Put_Unsigned_32 (Buffer, Interfaces.Unsigned_32 (Storage));
      Marshallers.Put_Unsigned_32 (Buffer, Buffers.Block_Size);
      Marshallers.Put_Unsigned_32 (Buffer, 0);
      Buffer.Buffer.Data.Value.Data (Buffer.Pos .. Buffers.Block_Type'Last) := (others => 0);
   end Build_Header;

   --  ------------------------------
   --  Read the header block and verify its integrity.
   --  ------------------------------
   procedure Read_Header (Header  : in out Wallet_Header) is
      Buf     : constant Buffers.Buffer_Accessor := Header.Buffer.Data.Value;
      Context : Util.Encoders.HMAC.SHA256.Context;
      Buffer  : Keystore.Marshallers.Marshaller;
      Value   : Interfaces.Unsigned_32;
      Value16       : Interfaces.Unsigned_16;
      Storage_Count : Interfaces.Unsigned_32;
   begin
      Buffer.Buffer := Header.Buffer;

      --  Verify values found in header block.
      Value := Marshallers.Get_Header (Buffer);
      if Value /= MAGIC_1 then
         Log.Warn ("Header magic 1 is invalid:{0}",
                   Interfaces.Unsigned_32'Image (Value));
         raise Invalid_Keystore;
      end if;
      Value := Marshallers.Get_Unsigned_32 (Buffer);
      if Value /= MAGIC_2 then
         Log.Warn ("Header magic 2 is invalid:{0}",
                   Interfaces.Unsigned_32'Image (Value));
         raise Invalid_Keystore;
      end if;
      Value := Marshallers.Get_Unsigned_32 (Buffer);
      if Value /= MAGIC_3 then
         Log.Warn ("Header magic 3 is invalid:{0}",
                   Interfaces.Unsigned_32'Image (Value));
         raise Invalid_Keystore;
      end if;
      Header.Version := Natural (Marshallers.Get_Unsigned_16 (Buffer));
      if Header.Version /= 1 then
         Log.Warn ("Header version is not supported:{0}",
                   Natural'Image (Header.Version));
         raise Invalid_Keystore;
      end if;
      Value := Interfaces.Unsigned_32 (Marshallers.Get_Unsigned_16 (Buffer));
      if Value /= 1 then
         Log.Warn ("Header block size bloc{0} is invalid:{0}",
                   Interfaces.Unsigned_32'Image (Value));
         raise Invalid_Keystore;
      end if;

      --  Get keystore UUID
      Marshallers.Get_UUID (Buffer, Header.UUID);
      Header.Identifier := Storage_Identifier (Marshallers.Get_Unsigned_32 (Buffer));
      if Header.Identifier /= Header.Buffer.Block.Storage then
         Log.Warn ("Header storage identifier does not match:{0}",
                   Storage_Identifier'Image (Header.Identifier));
         raise Invalid_Keystore;
      end if;
      Value := Marshallers.Get_Unsigned_32 (Buffer);
      if Value /= Buffers.Block_Size then
         Log.Warn ("Header block size is not supported:{0}",
                   Interfaces.Unsigned_32'Image (Value));
         raise Invalid_Keystore;
      end if;
      Header.Block_Size := Natural (Value);

      Storage_Count := Marshallers.Get_Unsigned_32 (Buffer);
      Header.Storage_Count := Natural (Storage_Count);

      Value16 := Marshallers.Get_Unsigned_16 (Buffer);
      if Value16 > Interfaces.Unsigned_16 (Header_Slot_Count_Type'Last) then
         Log.Warn ("Header data count is out of range:{0}",
                   Interfaces.Unsigned_16 'Image (Value16));
         raise Invalid_Keystore;
      end if;
      Header.Data_Count := Header_Slot_Count_Type (Value16);
   end Read_Header;

   --  ------------------------------
   --  Scan the header block for the storage and call the Process procedure for each
   --  storage information found in the header block.
   --  ------------------------------
   procedure Scan_Storage (Header  : in out Wallet_Header;
                           Process : not null access procedure (Storage : in Wallet_Storage)) is
      Buf     : constant Buffers.Buffer_Accessor := Header.Buffer.Data.Value;
      Buffer  : Keystore.Marshallers.Marshaller;
   begin
      Buffer.Buffer := Header.Buffer;
      for I in 1 .. Header.Storage_Count loop
         declare
            S      : Wallet_Storage;
            Status : Interfaces.Unsigned_16;
         begin
            Buffer.Pos := Get_Storage_Offset (I);
            S.Pos := Buffer.Pos + 1;
            S.Identifier := Storage_Identifier (Marshallers.Get_Unsigned_32 (Buffer));
            S.Kind := Marshallers.Get_Unsigned_16 (Buffer);
            Status := Marshallers.Get_Unsigned_16 (Buffer);
            S.Readonly := Status > 0;
            S.Sealed := Status > 0;
            S.Max_Block := Natural (Marshallers.Get_Unsigned_32 (Buffer));
            S.HMAC := Buf.Data (Buffer.Pos + 1 .. Buffer.Pos + 32);
            Process (S);
         end;
      end loop;
   end Scan_Storage;

   --  ------------------------------
   --  Sign the header block for the storage.
   --  ------------------------------
   procedure Sign_Header (Header  : in out Wallet_Header;
                          Sign    : in Secret_Key) is
      Buf     : constant Buffers.Buffer_Accessor := Header.Buffer.Data.Value;
      Context : Util.Encoders.HMAC.SHA256.Context;
   begin
      Util.Encoders.HMAC.SHA256.Set_Key (Context, Sign);
      Util.Encoders.HMAC.SHA256.Update (Context, Buf.Data);
      Util.Encoders.HMAC.SHA256.Finish (Context, Header.HMAC);
   end Sign_Header;

   procedure Seek_Header_Data (Buffer : in out Keystore.Marshallers.Marshaller;
                               Index  : in Header_Slot_Index_Type) is
      Size    : Buffer_Size;
   begin
      Buffer.Pos := HEADER_DATA_POS + 2 - 1;

      --  Skip entries until we reach the correct slot.
      for I in 1 .. Index - 1 loop
         Size := Marshallers.Get_Buffer_Size (Buffer);
         Marshallers.Skip (Buffer, Size + 2);
      end loop;
   end Seek_Header_Data;

   function Get_Header_Data_Size (Header : in Wallet_Header) return Buffer_Size is
      Buffer  : Keystore.Marshallers.Marshaller;
      Total   : Buffer_Size := 0;
      Size    : Buffer_Size;
   begin
      Buffer.Buffer := Header.Buffer;
      Buffer.Pos := HEADER_DATA_POS + 2 - 1;
      for I in 1 .. Header.Data_Count loop
         Size := Marshallers.Get_Buffer_Size (Buffer);
         Marshallers.Skip (Buffer, Size + 2);
         Total := Total + Size + 4;
      end loop;
      return Total;
   end Get_Header_Data_Size;

   --  ------------------------------
   --  Set some header data in the keystore file.
   --  ------------------------------
   procedure Set_Header_Data (Header : in out Wallet_Header;
                              Index  : in Header_Slot_Index_Type;
                              Kind   : in Header_Slot_Type;
                              Data   : in Ada.Streams.Stream_Element_Array) is
      Buf     : constant Buffers.Buffer_Accessor := Header.Buffer.Data.Value;
      Buffer  : Keystore.Marshallers.Marshaller;
      Size    : Buffer_Size;
      Last    : Block_Index;
      Space   : Stream_Element_Offset;
      Start   : Stream_Element_Offset;
      Limit   : constant Stream_Element_Offset := Get_Storage_Offset (Header.Storage_Count);
   begin
      if Index > Header.Data_Count + 1 then
         Log.Warn ("Not enough header slots to add a header data");
         raise No_Header_Slot;
      end if;
      Buffer.Buffer := Header.Buffer;
      Seek_Header_Data (Buffer, Index);
      if Index <= Header.Data_Count then
         Size := Marshallers.Get_Buffer_Size (Buffer);
         Space := Data'Length - Size;
         Buffer.Pos := Buffer.Pos - 2;
      else
         Space := Data'Length + 4;
      end if;

      Last := Get_Header_Data_Size (Header) + HEADER_DATA_POS;

      --  Verify there is enough room.
      if Last + Space + 4 >= Limit then
         Log.Warn ("Not enough header space to add a header data");
         raise No_Header_Slot;
      end if;

      --  Shift
      if Index < Header.Data_Count then
         Start := Buffer.Pos + 4 + Size;
         Buf.Data := Buf.Data (Start .. Last);
      end if;

      --  Update the header data slot.
      Marshallers.Put_Buffer_Size (Buffer, Data'Length);
      Marshallers.Put_Unsigned_16 (Buffer, Interfaces.Unsigned_16 (Kind));
      Buf.Data (Buffer.Pos + 1 .. Buffer.Pos + Data'Length) := Data;

      --  Update the header data count.
      if Index > Header.Data_Count then
         Header.Data_Count := Index;
      end if;
      Buffer.Pos := HEADER_DATA_POS - 1;
      Marshallers.Put_Unsigned_16 (Buffer, Interfaces.Unsigned_16 (Header.Data_Count));
   end Set_Header_Data;

   --  ------------------------------
   --  Get the header data information from the keystore file.
   --  ------------------------------
   procedure Get_Header_Data (Header : in out Wallet_Header;
                              Index  : in Header_Slot_Index_Type;
                              Kind   : out Header_Slot_Type;
                              Data   : out Ada.Streams.Stream_Element_Array;
                              Last   : out Ada.Streams.Stream_Element_Offset) is
      Buffer  : Keystore.Marshallers.Marshaller;
      Size    : Buffer_Size;
   begin
      if Index > Header.Data_Count then
         Kind := SLOT_EMPTY;
         Last := Data'First - 1;
         return;
      end if;
      Buffer.Buffer := Header.Buffer;
      Seek_Header_Data (Buffer, Index);

      --  Extract data slot and truncate if the buffer is too small.
      Size := Marshallers.Get_Buffer_Size (Buffer);
      Kind := Header_Slot_Type (Marshallers.Get_Unsigned_16 (Buffer));
      if Size > Data'Length then
         Size := Data'Length;
      end if;
      Marshallers.Get_Data (Buffer, Size, Data, Last);
   end Get_Header_Data;

   --  ------------------------------
   --  Add a new storage reference in the header and return its position in the header.
   --  Raises the No_Header_Slot if there is no room in the header.
   --  ------------------------------
   procedure Add_Storage (Header     : in out Wallet_Header;
                          Identifier : in Storage_Identifier;
                          Max_Block  : in Positive;
                          Pos        : out Block_Index) is
      Buffer : Keystore.Marshallers.Marshaller;
      Last   : constant Block_Index := Get_Header_Data_Size (Header) + HEADER_DATA_POS;
   begin
      Pos := Get_Storage_Offset (Header.Storage_Count + 1);
      if Pos <= Last + 4 then
         Log.Warn ("Not enough header space to add a new storage file");
         raise No_Header_Slot;
      end if;
      Buffer.Pos := Pos;
      Header.Storage_Count := Header.Storage_Count + 1;
      Buffer.Buffer := Header.Buffer;
      Marshallers.Put_Unsigned_32 (Buffer, Interfaces.Unsigned_32 (Identifier));
      Marshallers.Put_Unsigned_16 (Buffer, 0);
      Marshallers.Put_Unsigned_16 (Buffer, 0);
      Marshallers.Put_Unsigned_32 (Buffer, Interfaces.Unsigned_32 (Max_Block));

      Buffer.Pos := STORAGE_COUNT_POS - 1;
      Marshallers.Put_Unsigned_32 (Buffer, Interfaces.Unsigned_32 (Header.Storage_Count));
   end Add_Storage;

end Keystore.IO.Headers;
