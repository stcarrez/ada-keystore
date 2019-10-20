-----------------------------------------------------------------------
--  keystore-repository-keys -- Data keys management
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

with Keystore.Repository.Entries;
package body Keystore.Repository.Keys is

   use type Interfaces.Unsigned_32;
   use type Interfaces.Unsigned_64;

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
      Iterator.Item.Block_Count := Iterator.Item.Block_Count - Natural (Del_Count);
      Key_Start_Pos := Iterator.Key_Header_Pos - Key_Slot_Size (Iterator.Key_Count);

      Key_Pos := Iterator.Directory.Key_Pos;
      if Key_Pos < Key_Start_Pos then
         Buf.Data (Key_Pos + Del_Size .. Key_Start_Pos + Del_Size - 1)
           := Buf.Data (Key_Pos + 1 .. Key_Start_Pos);
      end if;
      Buf.Data (Key_Pos + 1 .. Key_Pos + Del_Size) := (others => 0);

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
      if Iterator.Directory = null or else Iterator.Directory.Available < DATA_KEY_ENTRY_SIZE
        or else Iterator.Key_Count = Key_Count_Type'Last
      then
         Entries.Find_Directory_Block (Manager, DATA_KEY_ENTRY_SIZE * 4, Iterator.Directory);
         Iterator.Directory.Available := Iterator.Directory.Available + DATA_KEY_ENTRY_SIZE * 4;
         if Iterator.Directory.Count > 0 then
            Entries.Load_Directory (Manager, Iterator.Directory, Iterator.Current);
         else
            Iterator.Current.Buffer := Manager.Current.Buffer;
         end if;
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
      begin
         --  Shift keys before the current slot.
         Key_Start := Iterator.Directory.Key_Pos;
         Key_Last := Iterator.Key_Last_Pos;
         if Key_Last /= Key_Start then
            Buf.Data (Key_Start - DATA_KEY_ENTRY_SIZE .. Key_Last - DATA_KEY_ENTRY_SIZE)
              := Buf.Data (Key_Start .. Key_Last);
         end if;

         --  Grow the key slot area by one key slot.
         Key_Last := Key_Last - DATA_KEY_ENTRY_SIZE;
         Key_Start := Key_Start - DATA_KEY_ENTRY_SIZE;
         Iterator.Key_Last_Pos := Key_Last;
         Iterator.Directory.Key_Pos := Key_Start;
         Iterator.Directory.Available := Iterator.Directory.Available - DATA_KEY_ENTRY_SIZE;
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
   begin
      pragma Assert (Iterator.Directory /= null);

      if Iterator.Data_Size /= Size then
         Iterator.Current.Pos := Iterator.Key_Pos - 2;
         Marshallers.Put_Buffer_Size (Iterator.Current, Size);
      end if;

      Manager.Modified.Include (Iterator.Current.Buffer.Block, Iterator.Current.Buffer.Data);
   end Update_Key_Slot;

end Keystore.Repository.Keys;
