-----------------------------------------------------------------------
--  keystore-repository-data -- Data access and management for the keystore
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
with Util.Log.Loggers;
with Ada.IO_Exceptions;
with Ada.Unchecked_Deallocation;
with Keystore.Logs;

--  Block = 4K, 8K, 16K, 64K, 128K ?
--
--  Data block start encrypted with wallet id, data encrypted with their own key
--  +------------------+
--  | Block HMAC-256   | 32b
--  +------------------+
--  | 03 03 03 03      | 4b
--  | Wallet id        | 4b
--  | PAD 0            | 4b
--  | PAD 0            | 4b
--  +------------------+-----
--  | Entry 1 ID       | 4b  Encrypted with wallet id
--  | Entry type       | 2b
--  | Slot size        | 2b
--  | Size 1           | 8b      Size < 4Kb and Slot size = Size
--  | Update date      | 8b
--  | Access date      | 8b
--  | Content IV       | 16b
--  | Content key      | 32b
--  | Content HMAC-256 | 32b => 112b
--  +------------------+-----
--  | Entry 2 ID       | 4b  Encrypted with wallet id
--  | Entry type       | 2b
--  | Slot size        | 2b
--  | Size 2           | 8b     Size > 4Kb and Slot size < Size
--  | Update date      | 8b
--  | Next block ID    | 4b
--  | 0 0 0 0          | 4b
--  | Content IV       | 16b
--  | Content key      | 32b
--  | Content HMAC-256 | 32b => 112b
--  +------------------+
--  | ...              |
--  +------------------+
--
--  Data block start encrypted with wallet id, data encrypted with their own key
--  +------------------+
--  | Block HMAC-256   | 32b
--  +------------------+
--  | 03 03 03 03      | 4b
--  | Wallet id        | 4b
--  | PAD 0            | 4b
--  | PAD 0            | 4b
--  +------------------+-----
--  | Entry 2 ID       | 4b  Encrypted with wallet id
--  | Entry type       | 2b
--  | Slot size        | 2b
--  | Size 2           | 8b     Size > 4Kb and Slot size < Size
--  | Access date      | 8b
--  | Next block ID    | 4b
--  | Data offset      | 4b
--  | Content IV       | 16b
--  | Content key      | 32b
--  | Content HMAC-256 | 32b => 112b
--  +------------------+
--  | Data content     |     Encrypted with entry key
--  +------------------+-----
--
--  Header: 32 + 16
--  Entry :      112
--  Entry-end:   16
--  Data:      3920   => 3%
package body Keystore.Repository.Data is

   use type Interfaces.Unsigned_16;
   use type Interfaces.Unsigned_32;
   use type Interfaces.Unsigned_64;
   use type IO.Block_Count;

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Keystore.Metadata");

   procedure Free is
     new Ada.Unchecked_Deallocation (Object => Wallet_Block_Entry,
                                     Name   => Wallet_Block_Entry_Access);

   --  Start offset of the data entry descriptor in the data block.
   function Data_Entry_Offset (Index : in Fragment_Index) return IO.Block_Index;

   --  ------------------------------
   --  Find the data block instance with the given block number.
   --  ------------------------------
   procedure Find_Data_Block (Manager    : in out Wallet_Manager;
                              Block      : in IO.Block_Number;
                              Data_Block : out Wallet_Block_Entry_Access) is
      Pos : constant Wallet_Block_Maps.Cursor := Manager.Data_List.Find (Block);
   begin
      if Wallet_Block_Maps.Has_Element (Pos) then
         Data_Block := Wallet_Block_Maps.Element (Pos);
         Data_Block.Count := Data_Block.Count + 1;
         return;
      end if;

      Data_Block := new Wallet_Block_Entry;
      Data_Block.Available := IO.Block_Index'Last - IO.BT_DATA_START + 1;
      Data_Block.Count := 1;
      Data_Block.Block := Block;
      Data_Block.Last_Pos := IO.Block_Index'Last;
      Manager.Data_List.Insert (Block, Data_Block);
   end Find_Data_Block;

   --  ------------------------------
   --  Find the data block to hold a new data entry that occupies the given space.
   --  The first data block that has enough space is used otherwise a new block
   --  is allocated and initialized.
   --  ------------------------------
   procedure Allocate_Data_Block (Manager    : in out Wallet_Manager;
                                  Space      : in IO.Block_Index;
                                  Data_Block : out Wallet_Block_Entry_Access;
                                  Stream     : in out IO.Wallet_Stream'Class) is
      Candidate : Wallet_Block_Entry_Access;
   begin
      loop
         --  Scan for a block having enough space for us.
         for Block of Manager.Data_List loop
            if Block.Available >= Space and Block.Count < Fragment_Index'Last then
               if Block.Ready then
                  Data_Block := Block;
                  return;
               end if;
               Candidate := Block;
            end if;
         end loop;

         exit when Candidate = null;

         Load_Data (Manager, Candidate, Manager.Buffer, Stream);
         Candidate := null;
      end loop;

      --  We need a new wallet directory block.
      Data_Block := new Wallet_Block_Entry;
      Data_Block.Available := IO.Block_Index'Last - IO.BT_DATA_START + 1;
      Data_Block.Count := 0;
      Data_Block.Last_Pos := IO.Block_Index'Last;
      Data_Block.Ready := True;
      Stream.Allocate (Data_Block.Block);
      Manager.Data_List.Insert (Data_Block.Block, Data_Block);

      Logs.Debug (Log, "Allocated data block{0}", Data_Block.Block);
   end Allocate_Data_Block;

   --  ------------------------------
   --  Release the data block to the stream.
   --  ------------------------------
   procedure Release_Data_Block (Manager    : in out Wallet_Manager;
                                 Data_Block : in out Wallet_Block_Entry_Access;
                                 Stream     : in out IO.Wallet_Stream'Class) is
      Pos : Wallet_Block_Maps.Cursor := Manager.Data_List.Find (Data_Block.Block);
   begin
      Manager.Data_List.Delete (Pos);
      Stream.Release (Block => Data_Block.Block);
      Free (Data_Block);
   end Release_Data_Block;

   --  ------------------------------
   --  Initialize the data block with an empty content.
   --  ------------------------------
   procedure Init_Data_Block (Manager    : in Wallet_Manager;
                              Buffer     : in out IO.Marshaller) is
   begin
      --  Prepare the new data block.
      Buffer.Data := (others => 0);
      IO.Set_Header (Into => Buffer,
                     Tag  => IO.BT_WALLET_DATA,
                     Id   => Interfaces.Unsigned_32 (Manager.Id));
   end Init_Data_Block;

   --  ------------------------------
   --  Load the data block in the wallet manager buffer.  Extract the data descriptors
   --  the first time the data block is read.
   --  ------------------------------
   procedure Load_Data (Manager    : in out Wallet_Manager;
                        Data_Block : in Wallet_Block_Entry_Access;
                        Buffer     : in out IO.Marshaller;
                        Stream     : in out IO.Wallet_Stream'Class) is
      --  We only decrypt the data entry descriptors.
      --  Size  : constant IO.Block_Index := IO.Block_Index (Data_Block.Count * DATA_ENTRY_SIZE);
      Btype : Interfaces.Unsigned_16;
      Wid   : Interfaces.Unsigned_32;
      Size  : IO.Block_Index;
   begin
      Logs.Debug (Log, "Load data block{0}", Data_Block.Block);

      --  Read wallet data block.
      Keys.Set_IV (Manager.Config.Data, Data_Block.Block);
      Stream.Read (Block        => Data_Block.Block,
                   Decipher     => Manager.Config.Data.Decipher,
                   Sign         => Manager.Config.Data.Sign,
                   Decrypt_Size => Size,
                   Into         => Buffer);

      --  Check block type.
      Btype := IO.Get_Unsigned_16 (Buffer);
      if Btype /= IO.BT_WALLET_DATA then
         Logs.Error (Log, "Block{0} invalid block type", Data_Block.Block);
         raise Keystore.Corrupted;
      end if;
      IO.Skip (Buffer, 2);

      --  Check that this is a block for the current wallet.
      Wid := IO.Get_Unsigned_32 (Buffer);
      if Wid /= Interfaces.Unsigned_32 (Manager.Id) then
         Logs.Error (Log, "Block{0} invalid block wallet identifier", Data_Block.Block);
         raise Keystore.Corrupted;
      end if;

      --  This is the first time we load this data block, scan the data descriptors.
      if not Data_Block.Ready then
         declare
            Offset    : IO.Block_Index := IO.Block_Index'Last;
            Pos       : Wallet_Indexs.Cursor;
            Item      : Wallet_Entry_Access;
            Index     : Interfaces.Unsigned_32;
            Data_Size : IO.Block_Index;
            Frag      : Fragment_Count := 0;
            Slot_Size : Interfaces.Unsigned_16;
            Item_Size : Interfaces.Unsigned_64;
            Next_Block  : Wallet_Block_Entry_Access;
            Block       : IO.Block_Count;
            Data_Offset : Interfaces.Unsigned_32;
         begin
            IO.Skip (Buffer, 8);

            while Buffer.Pos < IO.BT_DATA_START + Size loop
               Frag := Frag + 1;

               pragma Assert (Check => Buffer.Pos = Data_Entry_Offset (Frag));

               Index := IO.Get_Unsigned_32 (Buffer);
               exit when Index = 0;
               Pos := Manager.Entry_Indexes.Find (Wallet_Entry_Index (Index));
               if Wallet_Indexs.Has_Element (Pos) then
                  Item := Wallet_Indexs.Element (Pos);
                  Item.Kind := IO.Get_Kind (Buffer);
                  Slot_Size := IO.Get_Unsigned_16 (Buffer);
                  Item_Size := IO.Get_Unsigned_64 (Buffer);
                  Item.Size := Item_Size;
                  Next_Block := null;
                  if Item_Size = Interfaces.Unsigned_64 (Slot_Size) then
                     Item.Update_Date := IO.Get_Date (Buffer);
                     Item.Access_Date := IO.Get_Date (Buffer);
                     Data_Offset := 0;
                  else
                     Item.Access_Date := IO.Get_Date (Buffer);
                     Block := IO.Get_Block_Number (Buffer);
                     if Block /= 0 then
                        Find_Data_Block (Manager, Block, Next_Block);
                     end if;
                     Data_Offset := IO.Get_Unsigned_32 (Buffer);
                  end if;

                  --  Skip the IV, Key, HMAC-256
                  IO.Skip (Buffer, IO.SIZE_HMAC + IO.SIZE_SECRET + IO.SIZE_IV);

                  Data_Size := AES_Align (IO.Block_Index (Slot_Size));
                  Offset := Offset - Data_Size;
                  Data_Block.Available := Data_Block.Available - Data_Size - DATA_ENTRY_SIZE;
                  Data_Block.Last_Pos := Offset;
                  Data_Block.Fragments (Frag).Item := Item;
                  Data_Block.Fragments (Frag).Block_Offset := Offset;
                  Data_Block.Fragments (Frag).Size := IO.Block_Index (Slot_Size);
                  Data_Block.Fragments (Frag).Next_Fragment := Next_Block;
                  Data_Block.Fragments (Frag).Data_Offset := Stream_Element_Offset (Data_Offset);

               else
                  Logs.Error (Log, "Block{0} unkown index", Data_Block.Block);
                  raise Keystore.Corrupted;
               end if;
            end loop;
            Data_Block.Ready := True;
            Data_Block.Count := Frag;
         end;
      end if;

   exception
      when Ada.IO_Exceptions.End_Error | Ada.IO_Exceptions.Data_Error =>
         Logs.Error (Log, "Block{0} cannot be read", Data_Block.Block);
         raise Keystore.Corrupted;

   end Load_Data;

   --  ------------------------------
   --  Start offset of the data entry descriptor in the data block.
   --  ------------------------------
   function Data_Entry_Offset (Index : in Fragment_Index) return IO.Block_Index is
   begin
      return IO.BT_DATA_START + Stream_Element_Offset (Index * DATA_ENTRY_SIZE) - DATA_ENTRY_SIZE;
   end Data_Entry_Offset;

   --  ------------------------------
   --  Save the data block.
   --  ------------------------------
   procedure Save_Data (Manager    : in out Wallet_Manager;
                        Data_Block : in Wallet_Block_Entry;
                        Buffer     : in out IO.Marshaller;
                        Stream     : in out IO.Wallet_Stream'Class) is
      Encrypt_Size  : IO.Block_Index;
   begin
      Encrypt_Size := IO.Block_Index (Data_Block.Count * DATA_ENTRY_SIZE);

      Keystore.Logs.Debug (Log, "Save data block{0} encrypt{1}", Data_Block.Block, Encrypt_Size);

      Keys.Set_IV (Manager.Config.Data, Data_Block.Block);
      Stream.Write (Block        => Data_Block.Block,
                    From         => Buffer,
                    Encrypt_Size => Encrypt_Size,
                    Cipher       => Manager.Config.Data.Cipher,
                    Sign         => Manager.Config.Data.Sign);
   end Save_Data;

   --  ------------------------------
   --  Get the fragment position of the item within the data block.
   --  Returns 0 if the data item was not found.
   --  ------------------------------
   function Get_Fragment_Position (Data_Block : in Wallet_Block_Entry;
                                   Item       : in Wallet_Entry_Access) return Fragment_Count is
   begin
      for I in 1 .. Data_Block.Count loop
         if Data_Block.Fragments (I).Item = Item then
            return I;
         end if;
      end loop;

      return 0;
   end Get_Fragment_Position;

   --  ------------------------------
   --  Add in the data block the wallet data fragment with its content.
   --  The data block must have been loaded and is not saved.
   --  ------------------------------
   procedure Add_Fragment (Manager     : in out Wallet_Manager;
                           Work        : in Data_Work_Access;
                           Item        : in Wallet_Entry_Access;
                           Data_Offset : in Ada.Streams.Stream_Element_Offset;
                           Next_Block  : in Wallet_Block_Entry_Access;
                           Size        : in Ada.Streams.Stream_Element_Offset) is
      Data_Size     : constant IO.Block_Index := AES_Align (Size);
      Data_Block    : constant Wallet_Block_Entry_Access := Work.Data_Block;
   begin
      Logs.Debug (Log, "Add fragment block{0} at{1}", Data_Block.Block, Data_Block.Last_Pos);

      Data_Block.Count := Data_Block.Count + 1;

      --  Serialize the data entry at end of data entry area.
      Work.Block.Pos := Data_Entry_Offset (Data_Block.Count);
      IO.Put_Unsigned_32 (Work.Block, Interfaces.Unsigned_32 (Item.Id));
      IO.Put_Kind (Work.Block, Item.Kind);
      IO.Put_Unsigned_16 (Work.Block, Interfaces.Unsigned_16 (Size));
      IO.Put_Unsigned_64 (Work.Block, Item.Size);
      if Item.Size = Interfaces.Unsigned_64 (Size) then
         IO.Put_Date (Work.Block, Item.Update_Date);
         IO.Put_Date (Work.Block, Item.Access_Date);
      else
         IO.Put_Date (Work.Block, Item.Access_Date);
         if Next_Block /= null then
            IO.Put_Block_Number (Work.Block, Next_Block.Block);
         else
            IO.Put_Unsigned_32 (Work.Block, 0);
         end if;
         IO.Put_Unsigned_32 (Work.Block, Interfaces.Unsigned_32 (Data_Offset));
      end if;

      Data_Block.Available := Data_Block.Available - Data_Size - DATA_ENTRY_SIZE;
      Data_Block.Last_Pos := Data_Block.Last_Pos - Data_Size;

      --  Record the fragment in the data block.
      Data_Block.Fragments (Data_Block.Count).Item := Item;
      Data_Block.Fragments (Data_Block.Count).Data_Offset := Data_Offset;
      Data_Block.Fragments (Data_Block.Count).Size := Size;
      Data_Block.Fragments (Data_Block.Count).Next_Fragment := Next_Block;
      Data_Block.Fragments (Data_Block.Count).Block_Offset := Data_Block.Last_Pos;
      if Item.Data = null then
         Item.Data := Data_Block;
      end if;

      Work.Kind := DATA_ENCRYPT;
      Work.Start_Data := Data_Block.Last_Pos;
      Work.End_Data := Work.Start_Data + Data_Size - 1;
      --  Work.Buffer_Pos := 1;
      --  Work.Last_Pos := Content'Length;
      --  Work.Data (1 .. Content'Length) := Content;

   end Add_Fragment;

   --  ------------------------------
   --  Add in the data block the wallet data fragment with its content.
   --  The data block must have been loaded and is not saved.
   --  ------------------------------
   procedure Update_Fragment (Manager     : in out Wallet_Manager;
                              Data_Block  : in Wallet_Block_Entry_Access;
                              Item        : in Wallet_Entry_Access;
                              Data_Offset : in Ada.Streams.Stream_Element_Offset;
                              Position    : in Fragment_Index;
                              Fragment    : in Wallet_Block_Fragment;
                              Next_Block  : in Wallet_Block_Entry_Access;
                              Content     : in Ada.Streams.Stream_Element_Array) is
      Data_Size     : constant IO.Block_Index := AES_Align (Content'Length);
      Old_Size      : constant IO.Block_Index := Fragment.Size;
      Offset        : constant Stream_Element_Offset := AES_Align (Old_Size) - Data_Size;
      Cipher_Data   : Util.Encoders.AES.Encoder;
      IV            : Keystore.Secret_Key (Length => 16);
      Secret        : Keystore.Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      Start_Data    : IO.Block_Index;
      End_Data      : IO.Block_Index;
      Last_Encoded  : Ada.Streams.Stream_Element_Offset;
      Last_Pos      : Ada.Streams.Stream_Element_Offset;
   begin
      Logs.Debug (Log, "Update fragment block{0} at{1}", Data_Block.Block, Data_Block.Last_Pos);

      --  Serialize the data entry at its position.
      Manager.Buffer.Pos := Data_Entry_Offset (Position);
      IO.Put_Unsigned_32 (Manager.Buffer, Interfaces.Unsigned_32 (Item.Id));
      IO.Put_Kind (Manager.Buffer, Item.Kind);
      IO.Put_Unsigned_16 (Manager.Buffer, Content'Length);
      IO.Put_Unsigned_64 (Manager.Buffer, Item.Size);
      if Item.Size = Content'Length then
         IO.Put_Date (Manager.Buffer, Item.Update_Date);
         IO.Put_Date (Manager.Buffer, Item.Access_Date);
      else
         IO.Put_Date (Manager.Buffer, Item.Access_Date);
         if Next_Block /= null then
            IO.Put_Block_Number (Manager.Buffer, Next_Block.Block);
         else
            IO.Put_Unsigned_32 (Manager.Buffer, 0);
         end if;
         IO.Put_Unsigned_32 (Manager.Buffer, Interfaces.Unsigned_32 (Data_Offset));
      end if;

      IO.Get_Secret (Manager.Buffer, IV, Manager.Config.Data.Key, Manager.Config.Data.IV);
      IO.Get_Secret (Manager.Buffer, Secret, Manager.Config.Data.Key, Manager.Config.Data.IV);

      --  Make HMAC-SHA256 signature of the data content before encryption.
      IO.Put_HMAC_SHA256 (Manager.Buffer, Manager.Config.Data.Sign, Content);

      Data_Block.Fragments (Position).Size := Content'Length;
      Data_Block.Fragments (Position).Next_Fragment := Next_Block;
      if Item.Data = null then
         Item.Data := Data_Block;
      end if;

      pragma Assert (Check => Manager.Buffer.Pos = Data_Entry_Offset (Position + 1));

      Last_Pos := Data_Block.Last_Pos;
      Start_Data := Data_Block.Fragments (Position).Block_Offset + Offset;
      End_Data := Start_Data + Data_Size - 1;

      if Offset /= 0 then
         Data_Block.Fragments (Position).Block_Offset := Start_Data;
         Data_Block.Available := Data_Block.Available + Offset;
         Data_Block.Last_Pos := Data_Block.Last_Pos + Offset;

         --  Shift the data offset to take into account the move of data content.
         for J in Position + 1 .. Data_Block.Count loop
            Data_Block.Fragments (J).Block_Offset
              := Data_Block.Fragments (J).Block_Offset + Offset;
         end loop;

         --  Move the existing data for other values before we update the value.
         if Position /= Data_Block.Count then
            Manager.Buffer.Data (Last_Pos + Offset .. Start_Data - 1)
              := Manager.Buffer.Data (Last_Pos .. Start_Data - Offset - 1);
         end if;

         --  Erase the content that was dropped.
         if Offset > 0 then
            Manager.Buffer.Data (Last_Pos .. Last_Pos + Offset - 1) := (others => 0);
         end if;
      end if;

      --  Encrypt the data content using the item encryption key and IV.
      --  Cipher_Data.Set_IV (IV, (others => 0));
      Cipher_Data.Set_Key (Secret, Util.Encoders.AES.CBC);
      Cipher_Data.Set_Padding (Util.Encoders.AES.ZERO_PADDING);

      Cipher_Data.Transform (Data    => Content,
                             Into    => Manager.Buffer.Data (Start_Data .. End_Data),
                             Last    => Last_Pos,
                             Encoded => Last_Encoded);
      if Last_Pos < End_Data then
         Cipher_Data.Finish (Into => Manager.Buffer.Data (Last_Pos + 1 .. End_Data),
                             Last => Last_Pos);
      end if;

   end Update_Fragment;

   --  ------------------------------
   --  Get the data fragment and write it to the output buffer.
   --  ------------------------------
   procedure Get_Fragment (Manager  : in out Wallet_Manager;
                           Position : in Fragment_Index;
                           Fragment : in Wallet_Block_Fragment;
                           Output   : out Ada.Streams.Stream_Element_Array) is
      Start_Pos  : constant Stream_Element_Offset := Output'First;
      Last_Pos   : constant Stream_Element_Offset := Start_Pos + Fragment.Size - 1;
      Start_Data : constant IO.Block_Index := Fragment.Block_Offset;
      End_Data   : constant IO.Block_Index := Start_Data + AES_Align (Fragment.Size) - 1;
      Last       : Stream_Element_Offset;
      Encoded    : Stream_Element_Offset;
      Decipher   : Util.Encoders.AES.Decoder;
      Secret     : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      IV         : Secret_Key (Length => IO.SIZE_IV);
   begin
      Logs.Debug (Log, "Get fragment from{0} at{1}", Manager.Buffer.Block, Start_Data);

      Manager.Buffer.Pos := Data_Entry_Offset (Position) + DATA_IV_OFFSET;
      IO.Get_Secret (Manager.Buffer, IV, Manager.Config.Data.Key, Manager.Config.Data.IV);
      IO.Get_Secret (Manager.Buffer, Secret, Manager.Config.Data.Key, Manager.Config.Data.IV);

      --  Decipher.Set_IV (IV, (others => 0));
      Decipher.Set_Key (Secret, Util.Encoders.AES.CBC);
      Decipher.Set_Padding (Util.Encoders.AES.ZERO_PADDING);
      Decipher.Transform (Data    => Manager.Buffer.Data (Start_Data .. End_Data),
                          Into    => Output (Start_Pos .. Last_Pos),
                          Last    => Last,
                          Encoded => Encoded);
      Decipher.Finish (Into => Output (Last + 1 .. Last_Pos),
                       Last => Last);
   end Get_Fragment;

   --  ------------------------------
   --  Get the data fragment and write it to the output buffer.
   --  ------------------------------
   procedure Get_Fragment (Manager  : in out Wallet_Manager;
                           Position : in Fragment_Index;
                           Fragment : in Wallet_Block_Fragment;
                           Work     : in out Data_Work) is
      Start_Data : constant IO.Block_Index := Fragment.Block_Offset;
   begin
      Logs.Debug (Log, "Get fragment from{0} at{1}", Work.Block.Block, Start_Data);

      Work.Buffer_Pos := Work.Data'First;
      Work.Block.Pos := Data_Entry_Offset (Position) + DATA_IV_OFFSET;
      Work.Last_Pos := Work.Buffer_Pos + Fragment.Size - 1;
      Work.Start_Data := Start_Data;
      Work.End_Data := Start_Data + AES_Align (Fragment.Size) - 1;
   end Get_Fragment;

   --  ------------------------------
   --  Delete the data from the data block.
   --  The data block must have been loaded and is not saved.
   --  ------------------------------
   procedure Delete_Fragment (Manager    : in out Wallet_Manager;
                              Data_Block : in out Wallet_Block_Entry;
                              Next_Block : out Wallet_Block_Entry_Access;
                              Item       : in Wallet_Entry_Access) is
      Fragment_Pos  : Fragment_Count := 0;
   begin
      Keystore.Logs.Debug (Log, "Delete data from block{0}", Data_Block.Block);

      --  Unlink the item from the data block list and identify the data entry position.
      Fragment_Pos := Get_Fragment_Position (Data_Block, Item);
      if Fragment_Pos = 0 then
         Next_Block := null;
         return;
      end if;

      declare
         Fragment    : Wallet_Block_Fragment renames Data_Block.Fragments (Fragment_Pos);
         Data_Size   : constant IO.Block_Index := AES_Align (Fragment.Size);
         Last_Pos    : constant IO.Block_Index := Data_Block.Last_Pos;
         Start_Entry : IO.Block_Index;
         Last_Entry  : IO.Block_Index;
      begin
         Next_Block := Fragment.Next_Fragment;

         --  Shift the data offset to take into account the move of data content.
         for J in Fragment_Pos + 1 .. Data_Block.Count loop
            Data_Block.Fragments (J).Block_Offset
              := Data_Block.Fragments (J).Block_Offset + Data_Size;
         end loop;

         if Fragment_Pos /= Data_Block.Count then
            Data_Block.Fragments (Fragment_Pos .. Data_Block.Count - 1)
              := Data_Block.Fragments (Fragment_Pos + 1 .. Data_Block.Count);
         end if;

         --  Move the data entry.
         Last_Entry := Data_Entry_Offset (Data_Block.Count) + DATA_ENTRY_SIZE - 1;
         if Fragment_Pos /= Data_Block.Count then
            Start_Entry := Data_Entry_Offset (Fragment_Pos);
            Manager.Buffer.Data (Start_Entry .. Last_Entry - DATA_ENTRY_SIZE)
              := Manager.Buffer.Data (Start_Entry + DATA_ENTRY_SIZE .. Last_Entry);
         end if;
         Manager.Buffer.Data (Last_Entry - DATA_ENTRY_SIZE + 1 .. Last_Entry) := (others => 0);

         --  Move the data before the slot being removed.
         if Fragment.Block_Offset /= Last_Pos then
            Manager.Buffer.Data (Last_Pos + Data_Size .. Fragment.Block_Offset + Data_Size - 1)
              := Manager.Buffer.Data (Last_Pos .. Fragment.Block_Offset - 1);
         end if;

         --  Erase the content that was dropped.
         Manager.Buffer.Data (Last_Pos .. Last_Pos + Data_Size - 1) := (others => 0);
         Data_Block.Last_Pos := Data_Block.Last_Pos + Data_Size;
         Data_Block.Count := Data_Block.Count - 1;
         Data_Block.Available := Data_Block.Available + Data_Size + DATA_ENTRY_SIZE;
      end;
   end Delete_Fragment;

   procedure Fill (Work  : in out Data_Work;
                   Input : in out Util.Streams.Input_Stream'Class;
                   Space : in Buffer_Offset;
                   Last  : out Buffer_Size) is
      Pos   : Buffer_Offset := Work.Data'First;
      Limit : constant Buffer_Offset := Pos + Space - 1;
   begin
      Work.Buffer_Pos := 1;
      loop
         Input.Read (Work.Data (Pos .. Limit), Last);

         --  Reached end of buffer.
         if Last >= Limit then
            Work.Last_Pos := Limit;
            return;
         end if;

         --  Reached end of stream.
         if Last < Pos then
            if Last >= Work.Data'First then
               Work.Last_Pos := Pos;
            else
               Last := 0;
            end if;
            return;
         end if;
         Pos := Last + 1;
      end loop;
   end Fill;

   procedure Flush_Queue (Manager : in out Wallet_Manager;
                          Worker  : in out Wallet_Worker;
                          Stream  : in out IO.Wallet_Stream'Class) is
      Seq  : Natural;
      Work : Data_Work_Access;
   begin
      while Worker.Pool_Count < Worker.Work_Count loop
         Worker.Data_Queue.Dequeue (Work, Seq);
         Save_Data (Manager, Work.Data_Block.all, Work.Block, Stream);
         Put_Work (Worker, Work);
      end loop;
   end Flush_Queue;

   procedure Allocate_Work (Manager : in out Wallet_Manager;
                            Work    : out Data_Work_Access;
                            Stream  : in out IO.Wallet_Stream'Class) is
      Seq : Natural;
   begin
      loop
         Work := Get_Work (Manager.Workers.all);
         exit when Work /= null;
         Manager.Workers.Data_Queue.Dequeue (Work, Seq);
         Save_Data (Manager, Work.Data_Block.all, Work.Block, Stream);
         Put_Work (Manager.Workers.all, Work);
      end loop;
   end Allocate_Work;

   --  ------------------------------
   --  Write the data in one or several blocks.
   --  ------------------------------
   procedure Add_Data (Manager     : in out Wallet_Manager;
                       Item        : in Wallet_Entry_Access;
                       Data_Block  : in out Wallet_Block_Entry_Access;
                       Content     : in Ada.Streams.Stream_Element_Array;
                       Offset      : in out Ada.Streams.Stream_Element_Offset;
                       Stream      : in out IO.Wallet_Stream'Class) is
      Space       : Stream_Element_Offset;
      Last        : Stream_Element_Offset;
      Start       : Stream_Element_Offset := Content'First;
      Next_Block  : Wallet_Block_Entry_Access;
      Data_Offset : Stream_Element_Offset := Offset;
      Block       : Wallet_Block_Entry_Access := Data_Block;
      Sequence    : Natural := 0;
      Work        : Data_Work_Access;
   begin
      Manager.Workers.Data_Queue.Reset_Sequence;
      while Block /= null loop
         --  Check if the current block has enough space or we need another block.
         Space := Block.Available - DATA_ENTRY_SIZE;
         if Content'Last - Start + 1 >= Space then
            Last := Start + Space - 1;
            Block.Available := Block.Available - Space;
            Allocate_Data_Block (Manager, DATA_MAX_SIZE, Next_Block, Stream);
            Block.Available := Block.Available + Space;
--         elsif Full_Block then
--            Data_Block := Block;
--            Offset := Data_Offset;
--            return;
         else
            Last := Content'Last;
            Next_Block := null;
         end if;

         --  Get a data work instance or flush pending works to make one available.
         Allocate_Work (Manager, Work, Stream);
         Work.Sequence := Sequence;
         Work.Data_Block := Block;
         Sequence := Sequence + 1;

         --  Get the current block if it has some content or fill an empty new one.
         if Block.Count > 0 then
            Load_Data (Manager, Block, Work.Block, Stream);
         else
            Init_Data_Block (Manager, Work.Block);
            Work.Block.Block := Block.Block;
         end if;
         Work.Buffer_Pos := 1;
         Work.Last_Pos := Last - Start + 1;
         Work.Data (1 .. Work.Last_Pos) := Content (Start .. Last);
         Add_Fragment (Manager, Work, Item, Data_Offset, Next_Block, Last - Start + 1);

         if Manager.Workers.Work_Manager /= null then
            Manager.Workers.Work_Manager.Execute (Work.all'Access);
         else
            Work.Cipher;
            Put_Work (Manager.Workers.all, Work);
            Flush_Queue (Manager, Manager.Workers.all, Stream);
            Save_Data (Manager, Work.Data_Block.all, Work.Block, Stream);
         end if;

         --  Move on to what remains.
         Data_Offset := Data_Offset + Last - Start + 1;
         Start := Last + 1;
         Block := Next_Block;
      end loop;
      Offset := Data_Offset;
      Flush_Queue (Manager, Manager.Workers.all, Stream);
   end Add_Data;

   --  ------------------------------
   --  Write the data in one or several blocks.
   --  ------------------------------
   procedure Add_Data (Manager     : in out Wallet_Manager;
                       Item        : in Wallet_Entry_Access;
                       Data_Block  : in out Wallet_Block_Entry_Access;
                       Content     : in out Util.Streams.Input_Stream'Class;
                       Offset      : in out Ada.Streams.Stream_Element_Offset;
                       Stream      : in out IO.Wallet_Stream'Class) is
      Space       : Buffer_Offset;
      Last        : Buffer_Size;
      Next_Block  : Wallet_Block_Entry_Access;
      Data_Offset : Stream_Element_Offset := Offset;
      Block       : Wallet_Block_Entry_Access := Data_Block;
      Sequence    : Natural := 0;
      Work        : Data_Work_Access;
   begin
      Manager.Workers.Data_Queue.Reset_Sequence;
      while Block /= null loop
         --  Check if the current block has enough space or we need another block.
         Space := Block.Available - DATA_ENTRY_SIZE;

         --  Get a data work instance or flush pending works to make one available.
         Allocate_Work (Manager, Work, Stream);
         Work.Sequence := Sequence;
         Work.Data_Block := Block;
         Sequence := Sequence + 1;

         --  Fill the work buffer by reading the stream.
         Fill (Work.all, Content, Space, Last);
         if Last = 0 then
            Put_Work (Manager.Workers.all, Work);
            exit;
         end if;

         if Space = Last then
            Block.Available := Block.Available - Space;
            Allocate_Data_Block (Manager, DATA_MAX_SIZE, Next_Block, Stream);
            Block.Available := Block.Available + Space;
         else
            Next_Block := null;
         end if;

         --  Get the current block if it has some content or fill an empty new one.
         if Block.Count > 0 then
            Load_Data (Manager, Block, Work.Block, Stream);
         else
            Init_Data_Block (Manager, Work.Block);
            Work.Block.Block := Block.Block;
         end if;
         Add_Fragment (Manager, Work, Item, Data_Offset, Next_Block, Last);

         if Manager.Workers.Work_Manager /= null then
            Manager.Workers.Work_Manager.Execute (Work.all'Access);
         else
            Work.Cipher;
            Put_Work (Manager.Workers.all, Work);
            Flush_Queue (Manager, Manager.Workers.all, Stream);
            Save_Data (Manager, Work.Data_Block.all, Work.Block, Stream);
         end if;

         --  Move on to what remains.
         Data_Offset := Data_Offset + Last;
         Block := Next_Block;
      end loop;
      Offset := Data_Offset;
      Flush_Queue (Manager, Manager.Workers.all, Stream);
   end Add_Data;

   --  Update the data fragments.
   procedure Update_Data (Manager      : in out Wallet_Manager;
                          Item         : in Wallet_Entry_Access;
                          Data_Block   : in out Wallet_Block_Entry_Access;
                          Content      : in Ada.Streams.Stream_Element_Array;
                          Offset       : in out Ada.Streams.Stream_Element_Offset;
                          Full_Block   : in Boolean;
                          New_Block    : out Wallet_Block_Entry_Access;
                          Delete_Block : out Wallet_Block_Entry_Access;
                          Stream       : in out IO.Wallet_Stream'Class) is
      Start        : Stream_Element_Offset := Content'First;
      Last         : Stream_Element_Offset;
      Space        : Stream_Element_Offset;
      Next_Block   : Wallet_Block_Entry_Access;
      Position     : Fragment_Count;
      Kind         : constant Entry_Type := Item.Kind;
   begin
      New_Block := null;
      Delete_Block := null;
      while Data_Block /= null loop
         Load_Data (Manager, Data_Block, Manager.Buffer, Stream);
         Item.Kind := Kind;
         Item.Size := Interfaces.Unsigned_64 (Offset + Content'Length);
         Position := Get_Fragment_Position (Data_Block.all, Item);
         exit when Position = 0;

         --  See how much space we have in the current block.
         Space := Data_Block.Available + AES_Align (Data_Block.Fragments (Position).Size);
         if Space >= AES_Align (Content'Last - Start + 1) then
            Last := Content'Last;
            Delete_Block := Data_Block.Fragments (Position).Next_Fragment;
            Next_Block := null;
         else
            Last := Start + Space - 1;
            Next_Block := Data_Block.Fragments (Position).Next_Fragment;
            if Next_Block = null and Last < Content'Last then
               Allocate_Data_Block (Manager, DATA_MAX_SIZE, New_Block, Stream);
               Next_Block := New_Block;
            end if;
         end if;

         Update_Fragment (Manager, Data_Block, Item, Offset, Position,
                          Data_Block.Fragments (Position),
                          Next_Block, Content (Start .. Last));
         Offset := Offset + Data_Block.Fragments (Position).Size;
         Start := Last + 1;

         Save_Data (Manager, Data_Block.all, Manager.Buffer, Stream);
         Data_Block := Next_Block;
         exit when Last >= Content'Last or else New_Block /= null;
      end loop;
   end Update_Data;

   --  Erase the data fragments which are not used by the entry.
   procedure Delete_Data (Manager    : in out Wallet_Manager;
                          Item       : in Wallet_Entry_Access;
                          Data_Block : in Wallet_Block_Entry_Access;
                          Stream     : in out IO.Wallet_Stream'Class) is
      Block      : Wallet_Block_Entry_Access := Data_Block;
      Next_Block : Wallet_Block_Entry_Access;
   begin
      while Block /= null loop
         Load_Data (Manager, Block, Manager.Buffer, Stream);
         Delete_Fragment (Manager    => Manager,
                          Data_Block => Block.all,
                          Next_Block => Next_Block,
                          Item       => Item);
         if Block.Count = 0 then
            Release_Data_Block (Manager, Block, Stream);
         else
            Save_Data (Manager, Block.all, Manager.Buffer, Stream);
         end if;
         Block := Next_Block;
      end loop;
   end Delete_Data;

   --  ------------------------------
   --  Get the data associated with the named entry.
   --  ------------------------------
   procedure Get_Data (Manager    : in out Wallet_Manager;
                       Name       : in String;
                       Result     : out Entry_Info;
                       Output     : out Ada.Streams.Stream_Element_Array;
                       Stream     : in out IO.Wallet_Stream'Class) is
      Pos         : constant Wallet_Maps.Cursor := Manager.Map.Find (Name);
      Item        : Wallet_Entry_Access;
      Data_Block  : Wallet_Block_Entry_Access;
      Data_Offset : Ada.Streams.Stream_Element_Offset := Output'First;
      Position    : Fragment_Count;
   begin
      if not Wallet_Maps.Has_Element (Pos) then
         Log.Info ("Data entry '{0}' not found", Name);
         raise Not_Found;
      end if;

      Item := Wallet_Maps.Element (Pos);
      Data_Block := Item.Data;

      --  Load the data fragments.
      while Data_Block /= null loop
         Load_Data (Manager, Data_Block, Manager.Buffer, Stream);
         Position := Get_Fragment_Position (Data_Block.all, Item);
         exit when Position = 0;
         Get_Fragment (Manager, Position, Data_Block.Fragments (Position),
                       Output (Data_Offset .. Output'Last));
         Data_Offset := Data_Offset + Data_Block.Fragments (Position).Size;
         Data_Block := Data_Block.Fragments (Position).Next_Fragment;
      end loop;

      Result.Size := Natural (Item.Size);
      Result.Kind := Item.Kind;
      Result.Create_Date := Item.Create_Date;
      Result.Update_Date := Item.Update_Date;
   end Get_Data;

   procedure Write (Manager    : in out Wallet_Manager;
                    Name       : in String;
                    Output     : in out Util.Streams.Output_Stream'Class;
                    Stream     : in out IO.Wallet_Stream'Class) is
      Pos         : constant Wallet_Maps.Cursor := Manager.Map.Find (Name);
      Item        : Wallet_Entry_Access;
      Data_Block  : Wallet_Block_Entry_Access;
      Position    : Fragment_Count;
      Sequence    : Natural := 0;
      Seq         : Natural;
      Work        : Data_Work_Access;

      procedure Flush_Queue (Worker : in out Wallet_Worker) is
         Seq : Natural;
      begin
         while Worker.Pool_Count < Worker.Work_Count loop
            Worker.Data_Queue.Dequeue (Work, Seq);
            Output.Write (Work.Data (Work.Buffer_Pos .. Work.Last_Pos));
            Put_Work (Worker, Work);
         end loop;
      end Flush_Queue;

   begin
      if not Wallet_Maps.Has_Element (Pos) then
         Log.Info ("Data entry '{0}' not found", Name);
         raise Not_Found;
      end if;

      Manager.Workers.Data_Queue.Reset_Sequence;
      Item := Wallet_Maps.Element (Pos);
      Data_Block := Item.Data;

      --  Load the data fragments.
      while Data_Block /= null loop
         Work := Get_Work (Manager.Workers.all);
         if Work /= null then
            Work.Sequence := Sequence;
            Sequence := Sequence + 1;
            Load_Data (Manager, Data_Block, Work.Block, Stream);
            Position := Get_Fragment_Position (Data_Block.all, Item);
            exit when Position = 0;
            Get_Fragment (Manager, Position, Data_Block.Fragments (Position), Work.all);
            Data_Block := Data_Block.Fragments (Position).Next_Fragment;
            if Manager.Workers.Work_Manager /= null then
               Manager.Workers.Work_Manager.Execute (Work.all'Access);
            else
               Work.Decipher;
               Put_Work (Manager.Workers.all, Work);
               Flush_Queue (Manager.Workers.all);
               Output.Write (Work.Data (Work.Buffer_Pos .. Work.Last_Pos));
            end if;
         else
            Manager.Workers.Data_Queue.Dequeue (Work, Seq);
            Output.Write (Work.Data (Work.Buffer_Pos .. Work.Last_Pos));
            Put_Work (Manager.Workers.all, Work);
         end if;
      end loop;
      Flush_Queue (Manager.Workers.all);

   exception
      when E : others =>
         Log.Error ("Exception while decrypting data: {0}", E);
         Wait_Workers (Manager.Workers.all);
         raise;

   end Write;

   procedure Wait_Workers (Worker : in out Wallet_Worker) is
      Work : Data_Work_Access;
      Seq  : Natural;
   begin
      while Worker.Pool_Count < Worker.Work_Count loop
         Worker.Data_Queue.Dequeue (Work, Seq);
         Put_Work (Worker, Work);
      end loop;
   end Wait_Workers;

   procedure Put_Work (Worker : in out Wallet_Worker;
                       Work   : in Data_Work_Access) is
   begin
      Worker.Pool_Count := Worker.Pool_Count + 1;
      Worker.Work_Pool (Worker.Pool_Count) := Work;
   end Put_Work;

   function Get_Work (Worker : in out Wallet_Worker) return Data_Work_Access is
   begin
      if Worker.Pool_Count = 0 then
         return null;
      else
         Worker.Pool_Count := Worker.Pool_Count - 1;
         return Worker.Work_Pool (Worker.Pool_Count + 1);
      end if;
   end Get_Work;

   procedure Decipher (Work : in out Data_Work) is
      Last      : Stream_Element_Offset;
      Encoded   : Stream_Element_Offset;
      Start_Pos : constant Stream_Element_Offset := Work.Buffer_Pos;
      Last_Pos  : constant Stream_Element_Offset := Work.Last_Pos;
      Secret    : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      IV        : Secret_Key (Length => IO.SIZE_IV);
      Decipher  : Util.Encoders.AES.Decoder;
   begin
      Logs.Debug (Log, "Decipher from{0}", Work.Block.Block);

      IO.Get_Secret (Work.Block, IV, Work.Manager.Config.Data.Key,
                     Work.Manager.Config.Data.IV);
      IO.Get_Secret (Work.Block, Secret, Work.Manager.Config.Data.Key,
                     Work.Manager.Config.Data.IV);

      --  Decipher.Set_IV (IV, (others => 0));
      Decipher.Set_Key (Secret, Util.Encoders.AES.CBC);
      Decipher.Set_Padding (Util.Encoders.AES.ZERO_PADDING);

      Log.Debug ("Dump encrypted data:");
      Logs.Dump (Log, Work.Block.Data (Work.Start_Data .. Work.End_Data));
      Decipher.Transform
        (Data    => Work.Block.Data (Work.Start_Data .. Work.End_Data),
         Into    => Work.Data (Start_Pos .. Last_Pos),
         Last    => Last,
         Encoded => Encoded);

      Decipher.Finish (Into => Work.Data (Last + 1 .. Last_Pos),
                       Last => Last);
      Log.Debug ("Dump data:");
      Logs.Dump (Log, Work.Data (Start_Pos .. Last_Pos));

   end Decipher;

   procedure Cipher (Work : in out Data_Work) is
      Encoded   : Stream_Element_Offset;
      Start_Pos : constant Stream_Element_Offset := Work.Buffer_Pos;
      Last_Pos  : Stream_Element_Offset := Work.Last_Pos;
      Secret    : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      IV        : Secret_Key (Length => 16);
      Cipher    : Util.Encoders.AES.Encoder;
   begin
      --  Generate a new IV and key.
      Work.Random.Generate (IV);
      Work.Random.Generate (Secret);

      IO.Put_Secret (Work.Block, IV, Work.Manager.Config.Data.Key,
                     Work.Manager.Config.Data.IV);
      IO.Put_Secret (Work.Block, Secret, Work.Manager.Config.Data.Key,
                     Work.Manager.Config.Data.IV);

      --  Make HMAC-SHA256 signature of the data content before encryption.
      IO.Put_HMAC_SHA256 (Into    => Work.Block,
                          Key     => Work.Manager.Config.Data.Sign,
                          Content => Work.Data (Start_Pos .. Last_Pos));

      --  Encrypt the data content using the item encryption key and IV.
      --  Cipher.Set_IV (IV, (others => 0));
      Cipher.Set_Key (Secret, Util.Encoders.AES.CBC);
      Cipher.Set_Padding (Util.Encoders.AES.ZERO_PADDING);

      Log.Debug ("Dump clear data:");
      Logs.Dump (Log, Work.Data (Start_Pos .. Last_Pos));
      Cipher.Transform (Data    => Work.Data (Start_Pos .. Last_Pos),
                        Into    => Work.Block.Data (Work.Start_Data .. Work.End_Data),
                        Last    => Last_Pos,
                        Encoded => Encoded);
      if Last_Pos < Work.End_Data then
         Cipher.Finish (Into => Work.Block.Data (Last_Pos + 1 .. Work.End_Data),
                        Last => Last_Pos);
      end if;
      Log.Debug ("Dump encrypted data:");
      Logs.Dump (Log, Work.Block.Data (Work.Start_Data .. Work.End_Data));
   end Cipher;

   overriding
   procedure Execute (Work : in out Data_Work) is
   begin
      case Work.Kind is
         when DATA_ENCRYPT =>
            Work.Cipher;

         when DATA_DECRYPT =>
            Work.Decipher;

      end case;
      Work.Queue.Enqueue (Work'Unchecked_Access, Work.Sequence);
   end Execute;

   --  ------------------------------
   --  Create the wallet encryption and decryption work manager.
   --  ------------------------------
   function Create (Manager      : access Wallet_Manager;
                    Work_Manager : in Keystore.Task_Manager_Access;
                    Count        : in Positive) return Wallet_Worker_Access is
      Result : Wallet_Worker_Access := new Wallet_Worker (Count);
   begin
      Result.Work_Manager := Work_Manager;
      Result.Data_Queue.Set_Size (Capacity => Count);
      for I in 1 .. Count loop
         Result.Work_Pool (I) := Result.Work_Slots (I)'Access;
         Result.Work_Slots (I).Queue := Result.Data_Queue'Access;
         Result.Work_Slots (I).Manager := Manager;
      end loop;
      Result.Pool_Count := Count;
      return Result;
   end Create;

end Keystore.Repository.Data;
