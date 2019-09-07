-----------------------------------------------------------------------
--  keystore-repository-entries -- Repository management for the keystore
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
with Ada.IO_Exceptions;
with Ada.Unchecked_Deallocation;
with Keystore.Logs;

--
--  Wallet repository encrypted with Wallet directory key
--  +------------------+
--  | Block HMAC-256   | 32b
--  +------------------+
--  | 02 02            | 2b
--  | Encrypt size     | 2b = BT_DATA_LENGTH
--  | Wallet id        | 4b
--  | PAD 0            | 4b
--  | PAD 0            | 4b
--  +------------------+
--  | Next block ID    | 4b  Block number for next repository same storage
--  | Data key offset  | 2b  Starts at IO.Block_Index'Last, decreasing
--  +------------------+
--  | Entry ID         | 4b   ^
--  | Entry type       | 2b   |
--  | Name size        | 2b   |
--  | Name             | Nb   | DATA_NAME_ENTRY_SIZE + Name'Length
--  | Create date      | 8b   |
--  | Update date      | 8b   |
--  | Entry size       | 8b   v
--  +------------------+
--  | ...              |
--  +------------------+--
--  | 0 0 0 0          | 16b (End of name entry list)
--  +------------------+--
--  | ...              |     (random or zero)
--  +------------------+--
--  | 0 0 0 0          | 16b (End of data key list)
--  +------------------+--
--  | ...              |
--  +------------------+
--  | Storage ID       | 4b   ^ Repeats "Data key count" times
--  | Data block ID    | 4b   |
--  | Data size        | 2b   | DATA_KEY_ENTRY_SIZE = 58b
--  | Content IV       | 16b  |
--  | Content key      | 32b  v
--  +------------------+
--  | Entry ID         | 4b   ^
--  | Data key count   | 2b   | DATA_KEY_HEADER_SIZE = 10b
--  | Data offset      | 4b   v
--  +------------------+--
--
package body Keystore.Repository.Entries is

   use type Interfaces.Unsigned_32;

   Log : constant Util.Log.Loggers.Logger
     := Util.Log.Loggers.Create ("Keystore.Repository.Entries");

   procedure Free is
     new Ada.Unchecked_Deallocation (Object => Wallet_Entry,
                                     Name   => Wallet_Entry_Access);

   --  ------------------------------
   --  Load the wallet directory block in the wallet manager buffer.
   --  Extract the directory if this is the first time the data block is read.
   --  ------------------------------
   procedure Load_Directory (Manager   : in out Wallet_Manager;
                             Directory : in Wallet_Directory_Entry_Access;
                             Into      : in out IO.Marshaller) is
      Btype : Interfaces.Unsigned_16;
      Wid   : Interfaces.Unsigned_32;
      Size  : IO.Block_Index;
   begin
      Keystore.Logs.Debug (Log, "Load directory block{0}", Directory.Block);

      --  Get the directory block from the cache.
      Into.Buffer := Buffers.Find (Manager.Cache, Directory.Block);
      if not Buffers.Is_Null (Into.Buffer) then
         return;
      end if;

      Into.Buffer := Buffers.Find (Manager.Modified, Directory.Block);
      if not Buffers.Is_Null (Into.Buffer) then
         return;
      end if;

      --  Allocate block storage.
      Into.Buffer := Buffers.Allocate (Directory.Block);

      --  Read wallet meta data block.
      Keys.Set_IV (Manager.Config.Dir, Directory.Block.Block);
      Manager.Stream.Read (Decipher     => Manager.Config.Dir.Decipher,
                           Sign         => Manager.Config.Dir.Sign,
                           Decrypt_Size => Size,
                           Into         => Into.Buffer);
      Into.Pos := IO.BT_HEADER_START;

      --  Check block type.
      Btype := Marshallers.Get_Unsigned_16 (Into);
      if Btype /= IO.BT_WALLET_DIRECTORY then
         Logs.Error (Log, "Block{0} invalid block type", Directory.Block);
         raise Keystore.Corrupted;
      end if;
      Marshallers.Skip (Into, 2);

      --  Check that this is a block for the current wallet.
      Wid := Marshallers.Get_Unsigned_32 (Into);
      if Wid /= Interfaces.Unsigned_32 (Manager.Id) then
         Logs.Error (Log, "Block{0} invalid block wallet identifier", Directory.Block);
         raise Keystore.Corrupted;
      end if;

      --  This is the first time we load this directory block, scan the directory.
      if not Directory.Ready then
         Marshallers.Skip (Into, 8);

         declare
            Prev   : Wallet_Entry_Access := null;
            Item   : Wallet_Entry_Access;
            Index  : Interfaces.Unsigned_32;
            Count  : Interfaces.Unsigned_16;
            Offset : IO.Block_Index;
            Pos        : Wallet_Indexs.Cursor;
            Data_Key   : Wallet_Data_Key_Entry;
         begin
            Directory.Next_Block := Marshallers.Get_Unsigned_32 (Into);
            Directory.Key_Pos := Marshallers.Get_Block_Index (Into);

            --  Scan each named entry
            loop
               Offset := Into.Pos;
               Index := Marshallers.Get_Unsigned_32 (Into);
               exit when Index = 0;
               declare
                  Kind : constant Entry_Type := Marshallers.Get_Kind (Into);
                  Len  : constant Natural := Natural (Marshallers.Get_Unsigned_16 (Into));
                  Name : constant String := Marshallers.Get_String (Into, Len);
               begin
                  Item := new Wallet_Entry (Length => Len);
                  Item.Entry_Offset := Offset;
                  Item.Kind := Kind;
                  Item.Id := Wallet_Entry_Index (Index);
                  Item.Create_Date := Marshallers.Get_Date (Into);
                  Item.Update_Date := Marshallers.Get_Date (Into);
                  Item.Size := Marshallers.Get_Unsigned_64 (Into);
                  Item.Header := Directory;
                  Item.Name := Name;

                  if Prev = null then
                     Directory.First := Item;
                  else
                     Prev.Next_Entry := Item;
                  end if;
                  Prev := Item;
                  Item.Next_Entry := null;
                  if Item.Id >= Manager.Next_Id then
                     Manager.Next_Id := Item.Id + 1;
                  end if;

                  Manager.Map.Insert (Key => Name, New_Item => Item);
                  Manager.Entry_Indexes.Insert (Key => Item.Id, New_Item => Item);
                  Directory.Count := Directory.Count + 1;

               exception
                  when E : others =>
                     Free (Item);
                     Logs.Error (Log, "Block{0} contains invalid data entry", Directory.Block);
                     raise Keystore.Corrupted;
               end;
            end loop;
            Directory.Last_Pos := Into.Pos - 4;

            --  Scan each data key entry starting from the end of the directory block
            --  moving backward until we reach the directory key position.  For each data entry
            --  add a link to the directory block in 'Data_Blocks' list so that we can iterate
            --  over that list to get the whole data content for the data entry.
            Data_Key.Directory := Directory;
            Offset := IO.Block_Index'Last;
            while Offset > Directory.Key_Pos loop
               Offset := Offset - DATA_KEY_HEADER_SIZE;
               Into.Pos := Offset;
               Index := Marshallers.Get_Unsigned_32 (Into);
               Count := Marshallers.Get_Unsigned_16 (Into);

               --  Compute sum of sizes of every data block.
               Data_Key.Size := 0;
               while Count > 0 and Offset > Directory.Key_Pos loop
                  Offset := Offset - DATA_KEY_ENTRY_SIZE;

                  --  Set marshaller to the data key size position.
                  Into.Pos := Offset + 8;
                  Data_Key.Size := Data_Key.Size
                    + Stream_Element_Offset (Marshallers.Get_Unsigned_16 (Into));
                  Count := Count - 1;
               end loop;

               if Index /= 0 then
                  Pos := Manager.Entry_Indexes.Find (Wallet_Entry_Index (Index));
                  if Wallet_Indexs.Has_Element (Pos) then
                     Item := Wallet_Indexs.Element (Pos);
                     Item.Data_Blocks.Append (Data_Key);
                  end if;
               end if;
            end loop;
         end;
         Directory.Available := Directory.Key_Pos - Directory.Last_Pos - 4;
         Directory.Ready := True;
      end if;

   exception
      when Ada.IO_Exceptions.End_Error | Ada.IO_Exceptions.Data_Error =>
         Logs.Error (Log, "Block{0} cannot be read", Directory.Block);
         raise Keystore.Corrupted;

   end Load_Directory;

   --  ------------------------------
   --  Load the complete wallet directory by starting at the given block.
   --  ------------------------------
   procedure Load_Complete_Directory (Manager : in out Wallet_Manager;
                                      Block   : in Keystore.IO.Storage_Block) is
      Next      : Interfaces.Unsigned_32;
      Directory : Wallet_Directory_Entry_Access;
   begin
      Manager.Root := Block;
      Manager.Next_Id := Wallet_Entry_Index'First;
      Next := Interfaces.Unsigned_32 (Block.Block);
      while Next /= 0 loop
         Directory := new Wallet_Directory_Entry;
         Directory.Block := IO.Storage_Block '(Storage => Block.Storage,
                                               Block   => IO.Block_Number (Next));
         Manager.Directory_List.Append (Directory);
         Load_Directory (Manager, Directory, Manager.Current);

         Next := Directory.Next_Block;
      end loop;
   end Load_Complete_Directory;

   procedure Load_Next_Keys (Manager : in out Wallet_Manager;
                             Iterator : in out Data_Key_Iterator) is
      Index : Interfaces.Unsigned_32;
      Count : Interfaces.Unsigned_16;
      Offset : IO.Block_Index;
   begin
      Iterator.Directory := Wallet_Data_Key_List.Element (Iterator.Key_Iter).Directory;
      Load_Directory (Manager, Iterator.Directory, Iterator.Current);

      Iterator.Key_Header_Pos := Iterator.Directory.Key_Pos;
      Iterator.Key_Last_Pos := Iterator.Directory.Key_Pos;
      Iterator.Key_Count := 0;

      --  Scan each data key entry.
      Offset := IO.Block_Index'Last;
      while Offset > Iterator.Key_Header_Pos loop
         Offset := Offset - DATA_KEY_HEADER_SIZE;
         Iterator.Current.Pos := Offset;
         Index := Marshallers.Get_Unsigned_32 (Iterator.Current);
         Count := Marshallers.Get_Unsigned_16 (Iterator.Current);
         if Index = Interfaces.Unsigned_32 (Iterator.Entry_Id) then
            Iterator.Key_Header_Pos := Offset;
            Iterator.Current.Pos := Offset;
            Iterator.Key_Count := Count;
            Iterator.Count := Count;
            return;
         end if;

         Offset := Offset - Key_Slot_Size (Count);
      end loop;
   end Load_Next_Keys;

   procedure Initialize (Manager  : in out Wallet_Manager;
                         Iterator : in out Data_Key_Iterator;
                         Item     : in Wallet_Entry_Access) is
   begin
      Iterator.Key_Iter := Item.Data_Blocks.First;
      Iterator.Entry_Id := Item.Id;
      Iterator.Current_Offset := 0;
      Iterator.Key_Pos := IO.Block_Index'Last;
      Iterator.Count := 0;
      Iterator.Item := Item;
      if Wallet_Data_Key_List.Has_Element (Iterator.Key_Iter) then
         Load_Next_Keys (Manager, Iterator);
      else
         Iterator.Directory := null;
      end if;
   end Initialize;

   function Has_Data_Key (Iterator : in Data_Key_Iterator) return Boolean is
   begin
      return Iterator.Directory /= null;
   end Has_Data_Key;

   function Is_Last_Key (Iterator : in Data_Key_Iterator) return Boolean is
   begin
      return Iterator.Count = 0 and Iterator.Directory /= null;
   end Is_Last_Key;

   procedure Next_Data_Key (Manager  : in out Wallet_Repository;
                            Iterator : in out Data_Key_Iterator) is
      Pos : IO.Block_Index;
   begin
      loop
         --  Extract the next data key from the current directory block.
         if Iterator.Count > 0 then
            Iterator.Current.Pos := Iterator.Current.Pos - DATA_KEY_ENTRY_SIZE;
            Pos := Iterator.Current.Pos;
            Iterator.Data_Block := Marshallers.Get_Storage_Block (Iterator.Current);
            Iterator.Data_Size := Marshallers.Get_Buffer_Size (Iterator.Current);
            Iterator.Key_Pos := Iterator.Current.Pos;
            Iterator.Current.Pos := Pos;
            Iterator.Count := Iterator.Count - 1;
            return;
         end if;

         if not Wallet_Data_Key_List.Has_Element (Iterator.Key_Iter) then
            Iterator.Directory := null;
            return;
         end if;

         Wallet_Data_Key_List.Next (Iterator.Key_Iter);
         if not Wallet_Data_Key_List.Has_Element (Iterator.Key_Iter) then
            Iterator.Directory := null;
            return;
         end if;

         Load_Next_Keys (Manager, Iterator);
      end loop;
   end Next_Data_Key;

   procedure Mark_Data_Key (Iterator : in Data_Key_Iterator;
                            Mark     : in out Data_Key_Marker) is
   begin
      Mark.Directory := Iterator.Directory;
      Mark.Key_Header_Pos := Iterator.Key_Header_Pos;
      Mark.Key_Count := Iterator.Count;
   end Mark_Data_Key;

   procedure Delete_Key (Manager  : in out Wallet_Repository;
                         Iterator : in out Data_Key_Iterator;
                         Mark     : in out Data_Key_Marker) is
      Buf  : constant Buffers.Buffer_Accessor := Iterator.Current.Buffer.Data.Value;
      Key_Start_Pos : IO.Block_Index;
      Next_Iter     : Wallet_Data_Key_List.Cursor;
      Key_Pos       : IO.Block_Index;
      Del_Count     : Interfaces.Unsigned_16;
      Del_Size      : IO.Buffer_Size;
   begin
      if Mark.Key_Count = Iterator.Key_Count then
         --  Erase header + all keys
         Del_Count := Iterator.Key_Count;
         Del_Size := Key_Slot_Size (Del_Count) + DATA_KEY_HEADER_SIZE;
      else
         --  Erase some data keys but not all of them (the entry was updated and truncated).
         Del_Count := Iterator.Key_Count - Mark.Key_Count;
         Del_Size := Key_Slot_Size (Del_Count);
         Iterator.Current.Pos := Mark.Key_Header_Pos + 4;
         Marshallers.Put_Unsigned_16 (Iterator.Current, Mark.Key_Count);
      end if;
      Key_Start_Pos := Iterator.Key_Header_Pos - Key_Slot_Size (Iterator.Key_Count);

      Key_Pos := Iterator.Directory.Key_Pos;
      if Key_Pos < Key_Start_Pos then
         Buf.Data (Key_Pos + Del_Size .. Key_Start_Pos + Del_Size - 1)
           := Buf.Data (Key_Pos .. Key_Start_Pos - 1);
      end if;
      Buf.Data (Key_Pos .. Key_Pos + Del_Size - 1) := (others => 0);

      Iterator.Directory.Key_Pos := Key_Pos + Del_Size;
      if Iterator.Directory.Count > 0 or Iterator.Directory.Key_Pos < IO.Block_Index'Last then
         Iterator.Current.Pos := IO.BT_DATA_START + 4;
         Marshallers.Put_Block_Index (Iterator.Current, Iterator.Directory.Key_Pos);

         Manager.Modified.Include (Iterator.Current.Buffer.Block, Iterator.Current.Buffer.Data);
      else
         Manager.Stream.Release (Iterator.Directory.Block);
      end if;

      if Mark.Key_Count = Iterator.Key_Count then
         Next_Iter := Wallet_Data_Key_List.Next (Iterator.Key_Iter);
         Iterator.Item.Data_Blocks.Delete (Iterator.Key_Iter);
         Iterator.Key_Iter := Next_Iter;
      else

         if not Wallet_Data_Key_List.Has_Element (Iterator.Key_Iter) then
            Iterator.Directory := null;
            return;
         end if;

         Wallet_Data_Key_List.Next (Iterator.Key_Iter);
      end if;

      if not Wallet_Data_Key_List.Has_Element (Iterator.Key_Iter) then
         Iterator.Directory := null;
         return;
      end if;

      Load_Next_Keys (Manager, Iterator);
      Mark_Data_Key (Iterator, Mark);
   end Delete_Key;

   procedure Allocate_Key_Slot (Manager    : in out Wallet_Repository;
                                Iterator   : in out Data_Key_Iterator;
                                Data_Block : in IO.Storage_Block;
                                Size       : in IO.Buffer_Size;
                                Key_Pos    : out IO.Block_Index;
                                Key_Block  : out IO.Storage_Block) is
      Key_Start : IO.Block_Index;
      Key_Last  : IO.Block_Index;
   begin
      if Iterator.Directory = null or else Iterator.Directory.Available < DATA_KEY_ENTRY_SIZE then
         Find_Directory_Block (Manager, DATA_KEY_ENTRY_SIZE * 4, Iterator.Directory);
         Iterator.Directory.Available := Iterator.Directory.Available + DATA_KEY_ENTRY_SIZE * 4;
         if Iterator.Directory.Count > 0 then
            Load_Directory (Manager, Iterator.Directory, Iterator.Current);
         else
            Iterator.Current.Buffer := Buffers.Allocate (Iterator.Directory.Block);

            --  Prepare the new directory block.
            --  Fill the new block with random values or with zeros.
            if Manager.Randomize then
               Manager.Random.Generate (Iterator.Current.Buffer.Data.Value.Data);
            else
               Iterator.Current.Buffer.Data.Value.Data := (others => 0);
            end if;
            Marshallers.Set_Header (Into => Iterator.Current,
                                    Tag  => IO.BT_WALLET_DIRECTORY,
                                    Id   => Manager.Id);
            Marshallers.Put_Unsigned_32 (Iterator.Current, 0);
            Marshallers.Put_Block_Index (Iterator.Current, IO.Block_Index'Last);
         end if;
         Iterator.Key_Header_Pos := Iterator.Directory.Key_Pos - DATA_KEY_HEADER_SIZE;
         Iterator.Directory.Available := Iterator.Directory.Available - DATA_KEY_HEADER_SIZE;
         Iterator.Directory.Key_Pos := Iterator.Key_Header_Pos;
         Iterator.Key_Last_Pos := Iterator.Directory.Key_Pos;
         Iterator.Current.Pos := Iterator.Key_Header_Pos;
         Iterator.Key_Count := 0;
         Marshallers.Put_Unsigned_32 (Iterator.Current,
                                      Interfaces.Unsigned_32 (Iterator.Entry_Id));
         Marshallers.Put_Unsigned_16 (Iterator.Current, 0);
         Marshallers.Put_Unsigned_32 (Iterator.Current, 0);
         Iterator.Item.Data_Blocks.Append (Wallet_Data_Key_Entry '(Iterator.Directory, 0));
      end if;

      declare
         Buf       : constant Buffers.Buffer_Accessor := Iterator.Current.Buffer.Data.Value;
      begin
         --  Shift keys before the current slot.
         Key_Start := Iterator.Directory.Key_Pos;
         Key_Last := Iterator.Key_Last_Pos;
         if Key_Last /= Key_Start then
            Buf.Data (Key_Start - DATA_KEY_ENTRY_SIZE .. Key_Last - 1)
              := Buf.Data (Key_Start .. Key_Last - 1);
         end if;

         --  Grow the key slot area by one key slot.
         Iterator.Key_Last_Pos := Iterator.Key_Last_Pos - DATA_KEY_ENTRY_SIZE;
         Iterator.Directory.Key_Pos := Key_Start - DATA_KEY_ENTRY_SIZE;
         Iterator.Directory.Available := Iterator.Directory.Available - DATA_KEY_ENTRY_SIZE;
         Iterator.Current.Pos := IO.BT_DATA_START + 4;
         Marshallers.Put_Block_Index (Iterator.Current, Iterator.Directory.Key_Pos);

         --  Insert the new data key.
         Iterator.Key_Count := Iterator.Key_Count + 1;
         Iterator.Current.Pos := Iterator.Key_Header_Pos + 4;
         Marshallers.Put_Unsigned_16 (Iterator.Current, Iterator.Key_Count);
         Iterator.Current.Pos := Iterator.Key_Header_Pos - Key_Slot_Size (Iterator.Key_Count);
         Marshallers.Put_Storage_Block (Iterator.Current, Data_Block);
         Marshallers.Put_Buffer_Size (Iterator.Current, Size);
         Iterator.Key_Pos := Iterator.Current.Pos;

         Manager.Modified.Include (Iterator.Current.Buffer.Block, Iterator.Current.Buffer.Data);

         Key_Pos := Iterator.Key_Pos;
         Key_Block := Iterator.Current.Buffer.Block;
      end;
   end Allocate_Key_Slot;

   procedure Update_Key_Slot (Manager    : in out Wallet_Repository;
                              Iterator   : in out Data_Key_Iterator;
                              Size       : in IO.Buffer_Size) is
   begin
      pragma Assert (Iterator.Directory /= null);

      if Iterator.Data_Size /= Size then
         Iterator.Current.Pos := Iterator.Key_Pos - 2;
         Marshallers.Put_Unsigned_16 (Iterator.Current, Interfaces.Unsigned_16 (Size));

         Manager.Modified.Include (Iterator.Current.Buffer.Block, Iterator.Current.Buffer.Data);
      end if;
   end Update_Key_Slot;

   procedure Initialize_Directory_Block (Manager   : in out Wallet_Manager;
                                         Block     : in IO.Storage_Block;
                                         Space     : in IO.Buffer_Size;
                                         Directory : out Wallet_Directory_Entry_Access) is
   begin
      --  We need a new wallet directory block.
      Directory := new Wallet_Directory_Entry;
      Directory.Available := IO.Block_Index'Last - IO.BT_DATA_START - Space - 4 - 2;
      Directory.Count := 0;
      Directory.Key_Pos := IO.Block_Index'Last;
      Directory.Last_Pos := IO.BT_DATA_START + 4 + 2;
      Directory.Ready := True;
      Directory.Block := Block;

      Logs.Info (Log, "Adding directory block{0}", Directory.Block);

      if not Manager.Directory_List.Is_Empty then
         declare
            Last : constant Wallet_Directory_Entry_Access := Manager.Directory_List.Last_Element;
         begin
            --  Update the last directory block to link to the new one.
            Load_Directory (Manager, Last, Manager.Current);
            Last.Next_Block := Interfaces.Unsigned_32 (Directory.Block.Block);

            Manager.Current.Pos := IO.BT_DATA_START;
            Marshallers.Put_Block_Number (Manager.Current, Directory.Block.Block);

            Manager.Modified.Include (Manager.Current.Buffer.Block, Manager.Current.Buffer.Data);
         end;
      end if;

      Manager.Directory_List.Append (Directory);
   end Initialize_Directory_Block;

   --  ------------------------------
   --  Find and load a directory block to hold a new entry that occupies the given space.
   --  The first directory block that has enough space is used otherwise a new block
   --  is allocated and initialized.
   --  ------------------------------
   procedure Find_Directory_Block (Manager   : in out Wallet_Manager;
                                   Space     : in IO.Block_Index;
                                   Directory : out Wallet_Directory_Entry_Access) is
      Block : IO.Storage_Block;
   begin
      --  Scan for a block having enough space for us.
      for Block of Manager.Directory_List loop
         if Block.Available >= Space then
            Block.Available := Block.Available - Space;
            Block.Count := Block.Count + 1;
            Directory := Block;

            return;
         end if;
      end loop;

      Manager.Stream.Allocate (IO.DIRECTORY_BLOCK, Block);
      Initialize_Directory_Block (Manager, Block, Space, Directory);
   end Find_Directory_Block;

   --  ------------------------------
   --  Add a new entry in the wallet directory.
   --  ------------------------------
   procedure Add_Entry (Manager : in out Wallet_Manager;
                        Name    : in String;
                        Kind    : in Entry_Type;
                        Size    : in Interfaces.Unsigned_64;
                        Item    : out Wallet_Entry_Access) is
   begin
      if Manager.Map.Contains (Name) then
         Log.Info ("Name '{0}' is already used", Name);
         raise Name_Exist;
      end if;
      Log.Info ("Adding data entry {0}", Name);

      --  Create the new wallet entry.
      Item := new Wallet_Entry (Length => Name'Length);
      Item.Name := Name;
      Item.Create_Date := Ada.Calendar.Clock;
      Item.Update_Date := Item.Create_Date;
      Item.Id := Manager.Next_Id;
      Manager.Next_Id := Manager.Next_Id + 1;

      --  Find and load the directory block that can hold the new entry.
      Find_Directory_Block (Manager, Entry_Size (Item), Item.Header);

      --  Write the new entry at end of existing entries.
      Item.Entry_Offset := Item.Header.Last_Pos;

      --  Remember the last valid position for the next entry to add.
      Item.Header.Last_Pos := Item.Entry_Offset + Entry_Size (Item);
      Item.Header.Count := Item.Header.Count + 1;

      --  Register it in the local repository.
      Manager.Map.Insert (Name, Item);
      Manager.Entry_Indexes.Insert (Item.Id, Item);

      Update_Entry (Manager, Item, Kind, Size);
   end Add_Entry;

   --  ------------------------------
   --  Update an existing entry in the wallet directory.
   --  ------------------------------
   procedure Update_Entry (Manager : in out Wallet_Manager;
                           Item    : in Wallet_Entry_Access;
                           Kind    : in Entry_Type;
                           Size    : in Interfaces.Unsigned_64) is
   begin
      Item.Kind := Kind;
      Item.Size := Size;
      Item.Update_Date := Ada.Calendar.Clock;
      Item.Access_Date := Item.Update_Date;

      if Item.Header.Count > 0 then
         --  Find and load the directory block that can hold the new entry.
         Load_Directory (Manager, Item.Header, Manager.Current);
      else
         Manager.Current.Buffer := Buffers.Allocate (Item.Header.Block);

         --  Prepare the new directory block.
         --  Fill the new block with random values or with zeros.
         if Manager.Randomize then
            Manager.Random.Generate (Manager.Current.Buffer.Data.Value.Data);
         else
            Manager.Current.Buffer.Data.Value.Data := (others => 0);
         end if;
         Marshallers.Set_Header (Into => Manager.Current,
                                 Tag  => IO.BT_WALLET_DIRECTORY,
                                 Id   => Manager.Id);
         Marshallers.Put_Unsigned_32 (Manager.Current, 0);
         Marshallers.Put_Block_Index (Manager.Current, IO.Block_Index'Last);
      end if;

      --  Write the new entry.
      Manager.Current.Pos := Item.Entry_Offset;
      Marshallers.Put_Unsigned_32 (Manager.Current, Interfaces.Unsigned_32 (Item.Id));
      Marshallers.Put_Kind (Manager.Current, Item.Kind);
      Marshallers.Put_String (Manager.Current, Item.Name);
      Marshallers.Put_Date (Manager.Current, Item.Create_Date);
      Marshallers.Put_Date (Manager.Current, Item.Update_Date);
      Marshallers.Put_Unsigned_64 (Manager.Current, Item.Size);

      pragma Assert (Check => Manager.Current.Pos = Item.Entry_Offset + Entry_Size (Item));

      Manager.Modified.Include (Manager.Current.Buffer.Block, Manager.Current.Buffer.Data);
   end Update_Entry;

   --  ------------------------------
   --  Delete the entry from the repository.
   --  ------------------------------
   procedure Delete_Entry (Manager    : in out Wallet_Manager;
                           Item       : in Wallet_Entry_Access) is
      Directory    : constant Wallet_Directory_Entry_Access := Item.Header;
      Wallet_Entry : Wallet_Entry_Access;
      Prev_Entry   : Wallet_Entry_Access;
      Size         : IO.Block_Index;
      End_Entry    : IO.Block_Index;
   begin
      Keystore.Logs.Debug (Log, "Delete entry from block{0}", Directory.Block);

      Directory.Count := Directory.Count - 1;

      --  Load the directory block .
      Load_Directory (Manager, Directory, Manager.Current);

      declare
         Buf : constant Buffers.Buffer_Accessor := Manager.Current.Buffer.Data.Value;
      begin

         --  Unlink the item from the directory block list and identify the entry position.
         Wallet_Entry := Directory.First;
         while Wallet_Entry /= null and Wallet_Entry /= Item loop
            Prev_Entry := Wallet_Entry;
            Wallet_Entry := Wallet_Entry.Next_Entry;
         end loop;

         if Wallet_Entry = null then
            return;
         end if;
         if Prev_Entry /= null then
            Prev_Entry.Next_Entry := Item.Next_Entry;
         else
            Directory.First := Item.Next_Entry;
         end if;

         --  Move the data entry.
         Size := Entry_Size (Item);
         End_Entry := Item.Entry_Offset + Size;
         if End_Entry /= Directory.Last_Pos then
            Buf.Data (Item.Entry_Offset .. Directory.Last_Pos - Size - 1)
              := Buf.Data (End_Entry .. Directory.Last_Pos - 1);
         end if;
         if Manager.Randomize then
            --  When strong security is necessary, fill with random values
            --  (except the first 4 bytes).
            Buf.Data (Directory.Last_Pos - Size .. Directory.Last_Pos - Size + 3)
              := (others => 0);
            Manager.Random.Generate
              (Buf.Data (Directory.Last_Pos - Size + 4 .. Directory.Last_Pos));
         else
            Buf.Data (Directory.Last_Pos - Size .. Directory.Last_Pos) := (others => 0);
         end if;

         Directory.Last_Pos := Directory.Last_Pos - Size;

         Manager.Modified.Include (Manager.Current.Buffer.Block, Manager.Current.Buffer.Data);
      end;
   end Delete_Entry;

   --  ------------------------------
   --  Save the directory blocks that have been modified.
   --  ------------------------------
   procedure Save (Manager    : in out Wallet_Manager) is
      Buffer : Buffers.Storage_Buffer;
   begin
      while not Manager.Modified.Is_Empty loop
         Buffer.Block := Manager.Modified.First_Key;
         Buffer.Data := Manager.Modified.First_Element;
         Manager.Modified.Delete_First;
         Keys.Set_IV (Manager.Config.Dir, Buffer.Block.Block);
         Manager.Stream.Write (From         => Buffer,
                               Cipher       => Manager.Config.Dir.Cipher,
                               Sign         => Manager.Config.Dir.Sign);
      end loop;
   end Save;

end Keystore.Repository.Entries;
