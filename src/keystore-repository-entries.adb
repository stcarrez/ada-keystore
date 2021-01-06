-----------------------------------------------------------------------
--  keystore-repository-entries -- Repository management for the keystore
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
with Ada.IO_Exceptions;
with Ada.Unchecked_Deallocation;
with Keystore.Logs;
with Keystore.Marshallers;

--  === Directory Entries ===
--  The wallet repository block is encrypted with the wallet directory key.
--
--  ```
--  +------------------+
--  | 02 02            | 2b
--  | Encrypt size     | 2b = BT_DATA_LENGTH
--  | Wallet id        | 4b
--  | PAD 0            | 4b
--  | PAD 0            | 4b
--  +------------------+
--  | Next block ID    | 4b  Block number for next repository block with same storage
--  | Data key offset  | 2b  Starts at IO.Block_Index'Last, decreasing
--  +------------------+
--  | Entry ID         | 4b   ^
--  | Entry type       | 2b   | = T_STRING, T_BINARY
--  | Name size        | 2b   |
--  | Name             | Nb   | DATA_NAME_ENTRY_SIZE + Name'Length
--  | Create date      | 8b   |
--  | Update date      | 8b   |
--  | Entry size       | 8b   v
--  +------------------+
--  | Entry ID         | 4b   ^
--  | Entry type       | 2b   | = T_WALLET
--  | Name size        | 2b   |
--  | Name             | Nb   | DATA_NAME_ENTRY_SIZE + Name'Length
--  | Create date      | 8b   |
--  | Update date      | 8b   |
--  | Wallet lid       | 4b   |
--  | Wallet master ID | 4b   v
--  +------------------+
--  | ...              |
--  +------------------+--
--  | 0 0 0 0          | 4b (End of name entry list = DATA_KEY_SEPARATOR)
--  +------------------+--
--  | ...              |     (random or zero)
--  +------------------+--  <- = Data key offset
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
--  +------------------+
--  | Block HMAC-256   | 32b
--  +------------------+--
--  ```
--
package body Keystore.Repository.Entries is

   use type Interfaces.Unsigned_16;
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
      --  Get the directory block from the cache.
      Into.Buffer := Buffers.Find (Manager.Cache, Directory.Block);
      if not Buffers.Is_Null (Into.Buffer) then
         return;
      end if;

      --  Get it from the modified list in case it has some pending changes not written yet.
      Into.Buffer := Buffers.Find (Manager.Modified, Directory.Block);
      if not Buffers.Is_Null (Into.Buffer) then
         return;
      end if;

      Keystore.Logs.Info (Log, "Loading directory block{0}", Directory.Block);

      --  Allocate block storage.
      Into.Buffer := Buffers.Allocate (Directory.Block);

      --  Read wallet meta data block.
      Keys.Set_IV (Manager.Config.Dir, Directory.Block.Block);
      Manager.Stream.Read (Decipher     => Manager.Config.Dir.Decipher,
                           Sign         => Manager.Config.Dir.Sign,
                           Decrypt_Size => Size,
                           Into         => Into.Buffer);

      --  Check block type.
      Btype := Marshallers.Get_Header_16 (Into);
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
            Item     : Wallet_Entry_Access;
            Index    : Interfaces.Unsigned_32;
            Count    : Interfaces.Unsigned_16;
            Offset   : IO.Block_Index;
            Pos      : Wallet_Indexs.Cursor;
            Data_Key : Wallet_Data_Key_Entry;
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
               begin
                  --  Verify the length before allocating the entry.
                  exit when Len > Buffers.BT_DATA_SIZE;

                  --  Allocate the wallet entry.
                  Item := new Wallet_Entry (Length => Len, Is_Wallet => Kind = T_WALLET);
                  Marshallers.Get_String (Into, Item.Name);
                  Item.Entry_Offset := Offset;
                  Item.Kind := Kind;
                  Item.Id := Wallet_Entry_Index (Index);
                  Item.Create_Date := Marshallers.Get_Date (Into);
                  Item.Update_Date := Marshallers.Get_Date (Into);
                  if Kind = T_WALLET then
                     Item.Wallet_Id := Wallet_Identifier (Marshallers.Get_Unsigned_32 (Into));
                     Item.Master := Marshallers.Get_Block_Number (Into);
                  else
                     Item.Size := Marshallers.Get_Unsigned_64 (Into);
                  end if;
                  Item.Header := Directory;

                  if Item.Id >= Manager.Next_Id then
                     Manager.Next_Id := Item.Id + 1;
                  end if;

                  Manager.Map.Insert (Key => Item.Name, New_Item => Item);
                  Manager.Entry_Indexes.Insert (Key => Item.Id, New_Item => Item);
                  Directory.Count := Directory.Count + 1;

               exception
                  when others =>
                     Free (Item);
                     Logs.Error (Log, "Block{0} contains invalid data entry", Directory.Block);
                     --  It is better not to raise a corruption error but continue, this data block
                     --  is corrupted but we can still have valid entries in other blocks.
                     exit when Manager.Config.Ignore_Bad_Entry;
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

               if Index /= 0 then
                  Pos := Manager.Entry_Indexes.Find (Wallet_Entry_Index (Index));
                  if Wallet_Indexs.Has_Element (Pos) then
                     Item := Wallet_Indexs.Element (Pos);
                     Item.Data_Blocks.Append (Data_Key);
                     Item.Block_Count := Item.Block_Count + Natural (Count);
                  end if;
               end if;

               --  Compute sum of sizes of every data block.
               Data_Key.Size := 0;
               while Count > 0 and Offset > Directory.Key_Pos loop
                  Offset := Offset - DATA_KEY_ENTRY_SIZE;

                  --  Set marshaller to the data key size position.
                  Into.Pos := Offset + 8;
                  Data_Key.Size := Data_Key.Size + Marshallers.Get_Buffer_Size (Into);
                  Count := Count - 1;
               end loop;

            end loop;
         end;
         if Directory.Last_Pos + DATA_KEY_SEPARATOR < Directory.Key_Pos then
            Directory.Available := Directory.Key_Pos - Directory.Last_Pos - DATA_KEY_SEPARATOR;
         else
            Directory.Available := 0;
         end if;
         Directory.Ready := True;
      end if;

      --  Add the directory block in the cache if enabled.
      if Manager.Config.Cache_Directory then
         Manager.Cache.Include (Directory.Block, Into.Buffer.Data);
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

   procedure Initialize_Directory_Block (Manager   : in out Wallet_Manager;
                                         Block     : in IO.Storage_Block;
                                         Space     : in IO.Buffer_Size;
                                         Directory : out Wallet_Directory_Entry_Access) is
   begin
      --  We need a new wallet directory block.
      Directory := new Wallet_Directory_Entry;
      Directory.Available := IO.Block_Index'Last - IO.BT_DATA_START - Space - 4 - 2 - DATA_KEY_SEPARATOR;
      Directory.Count := 0;
      Directory.Key_Pos := IO.Block_Index'Last;
      Directory.Last_Pos := IO.BT_DATA_START + 4 + 2 - 1;
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

            Manager.Current.Pos := IO.BT_DATA_START - 1;
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
      Manager.Current.Buffer := Buffers.Allocate (Block);

      --  Prepare the new directory block.
      --  Fill the new block with random values or with zeros.
      if Manager.Config.Randomize then
         Manager.Random.Generate (Manager.Current.Buffer.Data.Value.Data);
      else
         Manager.Current.Buffer.Data.Value.Data := (others => 0);
      end if;
      Marshallers.Set_Header (Into => Manager.Current,
                              Tag  => IO.BT_WALLET_DIRECTORY,
                              Id   => Manager.Id);
      Marshallers.Put_Unsigned_32 (Manager.Current, 0);
      Marshallers.Put_Block_Index (Manager.Current, IO.Block_Index'Last);
      Marshallers.Put_Unsigned_32 (Manager.Current, 0);

      Keystore.Logs.Info (Log, "Allocated directory block{0}", Directory.Block);

      Manager.Modified.Include (Manager.Current.Buffer.Block, Manager.Current.Buffer.Data);

      --  Add the directory block in the cache if enabled.
      if Manager.Config.Cache_Directory then
         Manager.Cache.Include (Directory.Block, Manager.Current.Buffer.Data);
      end if;
   end Find_Directory_Block;

   --  ------------------------------
   --  Add a new entry in the wallet directory.
   --  ------------------------------
   procedure Add_Entry (Manager : in out Wallet_Manager;
                        Name    : in String;
                        Kind    : in Entry_Type;
                        Item    : out Wallet_Entry_Access) is
   begin
      if Manager.Map.Contains (Name) then
         Log.Info ("Name '{0}' is already used", Name);
         raise Name_Exist;
      end if;
      Log.Info ("Adding data entry {0}", Name);

      --  Create the new wallet entry.
      Item := new Wallet_Entry (Length => Name'Length, Is_Wallet => Kind = T_WALLET);
      Item.Name := Name;
      Item.Create_Date := Ada.Calendar.Clock;
      Item.Update_Date := Item.Create_Date;
      Item.Id := Manager.Next_Id;
      Item.Kind := Kind;
      Manager.Next_Id := Manager.Next_Id + 1;
      if Item.Is_Wallet then
         Item.Wallet_Id := Manager.Next_Wallet_Id;
         Manager.Next_Wallet_Id := Manager.Next_Wallet_Id + 1;
      end if;

      --  Find and load the directory block that can hold the new entry.
      Find_Directory_Block (Manager, Entry_Size (Item), Item.Header);

      --  Write the new entry at end of existing entries.
      Item.Entry_Offset := Item.Header.Last_Pos;

      --  Remember the last valid position for the next entry to add.
      Item.Header.Last_Pos := Item.Entry_Offset + Entry_Size (Item);
      Item.Header.Count := Item.Header.Count + 1;

      pragma Assert (Check => Item.Header.Last_Pos + DATA_KEY_SEPARATOR <= Item.Header.Key_Pos);

      --  Register it in the local repository.
      Manager.Map.Insert (Name, Item);
      Manager.Entry_Indexes.Insert (Item.Id, Item);
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
      if not Item.Is_Wallet then
         Item.Size := Size;
      end if;
      Item.Update_Date := Ada.Calendar.Clock;
      Item.Access_Date := Item.Update_Date;

      if Item.Header.Count > 0 then
         --  Find and load the directory block that can hold the new entry.
         Load_Directory (Manager, Item.Header, Manager.Current);
      end if;

      --  Write the new entry.
      Manager.Current.Pos := Item.Entry_Offset;
      Marshallers.Put_Unsigned_32 (Manager.Current, Interfaces.Unsigned_32 (Item.Id));
      Marshallers.Put_Kind (Manager.Current, Item.Kind);
      Marshallers.Put_String (Manager.Current, Item.Name);
      Marshallers.Put_Date (Manager.Current, Item.Create_Date);
      Marshallers.Put_Date (Manager.Current, Item.Update_Date);
      if Item.Is_Wallet then
         Marshallers.Put_Unsigned_32 (Manager.Current, Interfaces.Unsigned_32 (Item.Wallet_Id));
         Marshallers.Put_Block_Number (Manager.Current, Item.Master);
      else
         Marshallers.Put_Unsigned_64 (Manager.Current, Item.Size);
      end if;

      pragma Assert (Check => Manager.Current.Pos = Item.Entry_Offset + Entry_Size (Item));

      if Manager.Current.Pos = Item.Header.Last_Pos then
         Marshallers.Put_Unsigned_32 (Manager.Current, 0);
      end if;

      Manager.Modified.Include (Manager.Current.Buffer.Block, Manager.Current.Buffer.Data);
   end Update_Entry;

   --  ------------------------------
   --  Delete the entry from the repository.
   --  ------------------------------
   procedure Delete_Entry (Manager    : in out Wallet_Manager;
                           Item       : in Wallet_Entry_Access) is
      Directory    : constant Wallet_Directory_Entry_Access := Item.Header;
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
         --  Move the data entry.
         Size := Entry_Size (Item);
         End_Entry := Item.Entry_Offset + Size;
         if End_Entry /= Directory.Last_Pos then
            Buf.Data (Item.Entry_Offset + 1 .. Directory.Last_Pos - Size)
              := Buf.Data (End_Entry + 1 .. Directory.Last_Pos);
         end if;
         if Manager.Config.Randomize then
            --  When strong security is necessary, fill with random values
            --  (except the first DATA_KEY_SEPARATOR = 4 bytes).
            Buf.Data (Directory.Last_Pos - Size + 1
                        .. Directory.Last_Pos - Size + DATA_KEY_SEPARATOR)
              := (others => 0);
            Manager.Random.Generate
              (Buf.Data (Directory.Last_Pos - Size + DATA_KEY_SEPARATOR + 1
                           .. Directory.Last_Pos));
         else
            Buf.Data (Directory.Last_Pos - Size + 1 .. Directory.Last_Pos) := (others => 0);
         end if;

         Directory.Last_Pos := Directory.Last_Pos - Size;

         pragma Assert (Check => Directory.Last_Pos + DATA_KEY_SEPARATOR <= Directory.Key_Pos);

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
