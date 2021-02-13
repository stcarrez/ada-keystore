-----------------------------------------------------------------------
--  keystore-repository-keys -- Data keys management
--  Copyright (C) 2019, 2020 Stephane Carrez
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
with Keystore.Repository.Entries;
package body Keystore.Repository.Keys is

   use type Interfaces.Unsigned_32;
   use type Interfaces.Unsigned_64;

   Log : constant Util.Log.Loggers.Logger
     := Util.Log.Loggers.Create ("Keystore.Repository.Keys");

   procedure Load_Next_Keys (Manager  : in out Wallet_Manager;
                             Iterator : in out Data_Key_Iterator) is
      Index : Interfaces.Unsigned_32;
      Count : Interfaces.Unsigned_16;
      Offset : IO.Block_Index;
   begin
      Iterator.Directory := Wallet_Data_Key_List.Element (Iterator.Key_Iter).Directory;
      Entries.Load_Directory (Manager, Iterator.Directory, Iterator.Current);

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
            Iterator.Key_Last_Pos := Offset - Key_Slot_Size (Count);
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
      Iterator.Key_Count := 0;
      Iterator.Key_Header_Pos := IO.Block_Index'Last;
      Iterator.Key_Last_Pos := IO.Block_Index'Last;
      Iterator.Count := 0;
      Iterator.Item := Item;
      Iterator.Data_Size := 0;
      if Wallet_Data_Key_List.Has_Element (Iterator.Key_Iter) then
         Load_Next_Keys (Manager, Iterator);
         if Log.Get_Level >= Util.Log.INFO_LEVEL then
            Log.Info ("Item {0} has id{1} with{3} keys in block{2}",
                      Item.Name, Wallet_Entry_Index'Image (Item.Id),
                      Buffers.To_String (Iterator.Directory.Block),
                      Key_Count_Type'Image (Iterator.Key_Count));
         end if;
      else
         Iterator.Directory := null;
         if Log.Get_Level >= Util.Log.INFO_LEVEL then
            Log.Info ("Item {0} has id{1} with no key", Item.Name,
                      Wallet_Entry_Index'Image (Item.Id));
         end if;
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

   procedure Seek (Manager  : in out Wallet_Repository;
                   Offset   : in out Stream_Element_Offset;
                   Iterator : in out Data_Key_Iterator) is
      Data_Size : Stream_Element_Offset;
   begin
      loop
         Next_Data_Key (Manager, Iterator);
         exit when not Has_Data_Key (Iterator);
         Data_Size := Iterator.Data_Size;
         exit when Data_Size > Offset;
         Offset := Offset - Data_Size;
      end loop;
   end Seek;

   procedure Next_Data_Key (Manager  : in out Wallet_Repository;
                            Iterator : in out Data_Key_Iterator) is
      Pos : IO.Block_Index;
   begin
      Iterator.Current_Offset
        := Iterator.Current_Offset + Interfaces.Unsigned_64 (Iterator.Data_Size);
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
            Iterator.Data_Size := 0;
            return;
         end if;

         Wallet_Data_Key_List.Next (Iterator.Key_Iter);
         if not Wallet_Data_Key_List.Has_Element (Iterator.Key_Iter) then
            Iterator.Directory := null;
            Iterator.Data_Size := 0;
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
      Directory     : constant Wallet_Directory_Entry_Access := Iterator.Directory;
      Key_Start_Pos : IO.Block_Index;
      Next_Iter     : Wallet_Data_Key_List.Cursor;
      Key_Pos       : IO.Block_Index;
      Del_Count     : Key_Count_Type;
      Del_Size      : IO.Buffer_Size;
      New_Count     : Key_Count_Type;
   begin
      if Mark.Key_Count = Iterator.Key_Count then
         --  Erase header + all keys
         Del_Count := Iterator.Key_Count;
         Del_Size := Key_Slot_Size (Del_Count) + DATA_KEY_HEADER_SIZE;
      else
         --  Erase some data keys but not all of them (the entry was updated and truncated).
         Del_Count := Mark.Key_Count;
         Del_Size := Key_Slot_Size (Del_Count);
         Iterator.Current.Pos := Mark.Key_Header_Pos + 4;
         New_Count := Iterator.Key_Count - Mark.Key_Count;
         Marshallers.Put_Unsigned_16 (Iterator.Current, New_Count);
      end if;
      Iterator.Item.Block_Count := Iterator.Item.Block_Count - Natural (Del_Count);
      Key_Start_Pos := Iterator.Key_Header_Pos - Key_Slot_Size (Iterator.Key_Count);

      if Log.Get_Level >= Util.Log.INFO_LEVEL then
         Log.Info ("Delete{1} keys in block{0}@{3} keysize {2}",
                   Buffers.To_String (Directory.Block),
                   Key_Count_Type'Image (Del_Count),
                   Buffers.Image (Del_Size),
                   Buffers.Image (Key_Start_Pos));
      end if;

      Key_Pos := Directory.Key_Pos;
      if Key_Start_Pos /= Key_Pos then
         Buf.Data (Key_Pos + 1 + Del_Size .. Key_Start_Pos + Del_Size)
           := Buf.Data (Key_Pos + 1 .. Key_Start_Pos);
      end if;
      Buf.Data (Key_Pos + 1 .. Key_Pos + Del_Size) := (others => 0);

      --  Release Del_Size bytes from the directory block.
      Directory.Key_Pos := Key_Pos + Del_Size;

      pragma Assert (Check => Directory.Last_Pos + DATA_KEY_SEPARATOR <= Directory.Key_Pos);

      Directory.Available := Directory.Available + Del_Size;
      Iterator.Current.Pos := IO.BT_DATA_START + 4 - 1;
      Marshallers.Put_Block_Index (Iterator.Current, Directory.Key_Pos);

      Manager.Modified.Include (Iterator.Current.Buffer.Block, Iterator.Current.Buffer.Data);

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

   procedure Prepare_Append (Iterator : in out Data_Key_Iterator) is
   begin
      Iterator.Key_Iter := Iterator.Item.Data_Blocks.Last;
      if Wallet_Data_Key_List.Has_Element (Iterator.Key_Iter) then
         Iterator.Directory := Wallet_Data_Key_List.Element (Iterator.Key_Iter).Directory;
      end if;
   end Prepare_Append;

   procedure Allocate_Key_Slot (Manager    : in out Wallet_Repository;
                                Iterator   : in out Data_Key_Iterator;
                                Data_Block : in IO.Storage_Block;
                                Size       : in IO.Buffer_Size;
                                Key_Pos    : out IO.Block_Index;
                                Key_Block  : out IO.Storage_Block) is
      Key_Start : IO.Block_Index;
      Key_Last  : IO.Block_Index;
   begin
      if Iterator.Directory = null
        or else Iterator.Directory.Available < DATA_KEY_ENTRY_SIZE + DATA_KEY_HEADER_SIZE
        or else Iterator.Key_Count = Key_Count_Type'Last
      then
         --  Get a directory block with enough space to hold several keys.
         Entries.Find_Directory_Block (Manager, DATA_KEY_ENTRY_SIZE * 4, Iterator.Directory);
         Iterator.Directory.Available := Iterator.Directory.Available + DATA_KEY_ENTRY_SIZE * 4;
         if Iterator.Directory.Count > 0 then
            Entries.Load_Directory (Manager, Iterator.Directory, Iterator.Current);
         else
            Iterator.Current.Buffer := Manager.Current.Buffer;
         end if;

         --  Setup the new entry key slot and take room for the key header.
         Iterator.Key_Header_Pos := Iterator.Directory.Key_Pos - DATA_KEY_HEADER_SIZE;
         Iterator.Directory.Available := Iterator.Directory.Available - DATA_KEY_HEADER_SIZE;
         Iterator.Directory.Key_Pos := Iterator.Key_Header_Pos;
         Iterator.Key_Last_Pos := Iterator.Key_Header_Pos;
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
         Directory : constant Wallet_Directory_Entry_Access := Iterator.Directory;
      begin
         --  Shift keys before the current slot.
         Key_Start := Directory.Key_Pos;
         Key_Last := Iterator.Key_Last_Pos;
         if Key_Last /= Key_Start then
            Buf.Data (Key_Start - DATA_KEY_ENTRY_SIZE .. Key_Last - DATA_KEY_ENTRY_SIZE)
              := Buf.Data (Key_Start .. Key_Last);
         end if;

         --  Grow the key slot area by one key slot.
         Key_Last := Key_Last - DATA_KEY_ENTRY_SIZE;
         Key_Start := Key_Start - DATA_KEY_ENTRY_SIZE;
         Iterator.Key_Last_Pos := Key_Last;
         Directory.Key_Pos := Key_Start;

         pragma Assert (Check => Directory.Last_Pos + DATA_KEY_SEPARATOR <= Directory.Key_Pos);

         Directory.Available := Directory.Available - DATA_KEY_ENTRY_SIZE;
         Iterator.Current.Pos := IO.BT_DATA_START + 4 - 1;
         Marshallers.Put_Block_Index (Iterator.Current, Key_Start);

         --  Insert the new data key.
         Iterator.Key_Count := Iterator.Key_Count + 1;
         Iterator.Current.Pos := Iterator.Key_Header_Pos + 4;
         Marshallers.Put_Unsigned_16 (Iterator.Current, Iterator.Key_Count);
         Iterator.Current.Pos := Iterator.Key_Header_Pos - Key_Slot_Size (Iterator.Key_Count);
         Marshallers.Put_Storage_Block (Iterator.Current, Data_Block);
         Marshallers.Put_Buffer_Size (Iterator.Current, Size);
         Iterator.Key_Pos := Iterator.Current.Pos;

         Manager.Modified.Include (Iterator.Current.Buffer.Block, Iterator.Current.Buffer.Data);

         Iterator.Item.Block_Count := Iterator.Item.Block_Count + 1;
         Key_Pos := Iterator.Key_Pos;
         Key_Block := Iterator.Current.Buffer.Block;
      end;
   end Allocate_Key_Slot;

   procedure Update_Key_Slot (Manager    : in out Wallet_Repository;
                              Iterator   : in out Data_Key_Iterator;
                              Size       : in IO.Buffer_Size) is
      Pos : IO.Block_Index;
   begin
      pragma Assert (Iterator.Directory /= null);

      if Iterator.Data_Size /= Size then
         Pos := Iterator.Current.Pos;
         Iterator.Current.Pos := Iterator.Key_Pos - 2;
         Marshallers.Put_Buffer_Size (Iterator.Current, Size);
         Iterator.Current.Pos := Pos;
      end if;

      Manager.Modified.Include (Iterator.Current.Buffer.Block, Iterator.Current.Buffer.Data);
   end Update_Key_Slot;

   procedure Create_Wallet (Manager      : in out Wallet_Repository;
                            Item         : in Wallet_Entry_Access;
                            Master_Block : in Keystore.IO.Storage_Block;
                            Keys         : in out Keystore.Keys.Key_Manager) is
      Iter      : Data_Key_Iterator;
      Key_Pos   : IO.Block_Index;
      Key_Block : IO.Storage_Block;
   begin
      Initialize (Manager, Iter, Item);

      Allocate_Key_Slot (Manager, Iter, Master_Block, IO.Buffer_Size'Last, Key_Pos, Key_Block);

      Iter.Current.Pos := Key_Pos;
      Keystore.Keys.Create_Master_Key (Keys, Iter.Current, Manager.Config.Key);
   end Create_Wallet;

   procedure Open_Wallet (Manager : in out Wallet_Repository;
                          Item    : in Wallet_Entry_Access;
                          Keys    : in out Keystore.Keys.Key_Manager) is
      Iter : Data_Key_Iterator;
   begin
      Initialize (Manager, Iter, Item);
      Next_Data_Key (Manager, Iter);

      pragma Assert (Has_Data_Key (Iter));

      Iter.Current.Pos := Iter.Key_Pos;
      Keystore.Keys.Load_Master_Key (Keys, Iter.Current, Manager.Config.Key);
   end Open_Wallet;

end Keystore.Repository.Keys;
