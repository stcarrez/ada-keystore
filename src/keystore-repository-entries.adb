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
with Keystore.Repository.Data;

--
--  Wallet repository encrypted with Wallet directory key
--  +------------------+
--  | Block HMAC-256   | 32b
--  +------------------+
--  | 02 02            | 2b
--  | Encrypt size     | 2b
--  | Wallet id        | 4b
--  | PAD 0            | 4b
--  | PAD 0            | 4b
--  +------------------+
--  | Next block ID    | 4b  Block number for next repository
--  +------------------+
--  | Entry ID         | 4b
--  | Name size        | 2b
--  | Name             | Nb
--  | Create date      | 8b
--  | Data block ID    | 4b
--  +------------------+
--  | ...              |
--  +------------------+--
--
package body Keystore.Repository.Entries is

   use type Interfaces.Unsigned_16;
   use type Interfaces.Unsigned_32;
   use type Interfaces.Unsigned_64;
   use type IO.Block_Count;

   Log : constant Util.Log.Loggers.Logger
     := Util.Log.Loggers.Create ("Keystore.Repository.Entries");

   procedure Free is
     new Ada.Unchecked_Deallocation (Object => Wallet_Entry,
                                     Name   => Wallet_Entry_Access);

   --  Size of the wallet entry in the repository.
   function Entry_Size (Item : in Wallet_Entry_Access) return IO.Block_Index;

   --  ------------------------------
   --  Load the wallet directory block in the wallet manager buffer.
   --  Extract the directory if this is the first time the data block is read.
   --  ------------------------------
   procedure Load_Directory (Manager   : in out Wallet_Manager;
                             Dir_Block : in Wallet_Directory_Entry_Access;
                             Stream    : in out IO.Wallet_Stream'Class) is
      Btype : Interfaces.Unsigned_16;
      Wid   : Interfaces.Unsigned_32;
      Size  : IO.Block_Index;
   begin
      Keystore.Logs.Debug (Log, "Load directory block{0}", Dir_Block.Block);

      --  Read wallet meta data block.
      Keys.Set_IV (Manager.Config.Dir, Dir_Block.Block);
      Stream.Read (Block        => Dir_Block.Block,
                   Decipher     => Manager.Config.Dir.Decipher,
                   Sign         => Manager.Config.Dir.Sign,
                   Decrypt_Size => Size,
                   Into         => Manager.Buffer);

      --  Check block type.
      Btype := IO.Get_Unsigned_16 (Manager.Buffer);
      if Btype /= IO.BT_WALLET_REPOSITORY then
         Logs.Error (Log, "Block{0} invalid block type", Dir_Block.Block);
         raise Keystore.Corrupted;
      end if;
      IO.Skip (Manager.Buffer, 2);

      --  Check that this is a block for the current wallet.
      Wid := IO.Get_Unsigned_32 (Manager.Buffer);
      if Wid /= Interfaces.Unsigned_32 (Manager.Id) then
         Logs.Error (Log, "Block{0} invalid block wallet identifier", Dir_Block.Block);
         raise Keystore.Corrupted;
      end if;

      --  This is the first time we load this directory block, scan the directory.
      if not Dir_Block.Ready then
         declare
            Prev   : Wallet_Entry_Access := null;
            Item   : Wallet_Entry_Access;
            Index  : Interfaces.Unsigned_32;
            Offset : IO.Block_Index;
         begin
            IO.Skip (Manager.Buffer, 8);
            Dir_Block.Next_Block := IO.Get_Unsigned_32 (Manager.Buffer);

            --  Scan each entry
            loop
               Offset := Manager.Buffer.Pos;
               Index := IO.Get_Unsigned_32 (Manager.Buffer);
               exit when Index = 0;
               declare
                  Len  : constant Natural := Natural (IO.Get_Unsigned_16 (Manager.Buffer));
                  Name : constant String := IO.Get_String (Manager.Buffer, Len);
               begin
                  Item := new Wallet_Entry (Length => Len);
                  Item.Entry_Offset := Offset;
                  Item.Id := Wallet_Entry_Index (Index);
                  Item.Create_Date := IO.Get_Date (Manager.Buffer);
                  Item.Header := Dir_Block;
                  Item.Name := Name;
                  Data.Find_Data_Block (Manager, IO.Get_Block_Number (Manager.Buffer), Item.Data);

                  if Prev = null then
                     Dir_Block.First := Item;
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
                  Dir_Block.Count := Dir_Block.Count + 1;

               exception
                  when E : others =>
                     Free (Item);
                     Logs.Error (Log, "Block{0} contains invalid data entry", Dir_Block.Block);
                     raise Keystore.Corrupted;
               end;
            end loop;
            Dir_Block.Last_Pos := Manager.Buffer.Pos - 4;
         end;
         Dir_Block.Ready := True;
      end if;

   exception
      when Ada.IO_Exceptions.End_Error | Ada.IO_Exceptions.Data_Error =>
         Logs.Error (Log, "Block{0} cannot be read", Dir_Block.Block);
         raise Keystore.Corrupted;

   end Load_Directory;

   --  ------------------------------
   --  Load the complete wallet directory by starting at the given block.
   --  ------------------------------
   procedure Load_Complete_Directory (Manager : in out Wallet_Manager;
                                      Block   : in Keystore.IO.Block_Number;
                                      Stream  : in out IO.Wallet_Stream'Class) is
      Next      : Interfaces.Unsigned_32;
      Dir_Block : Wallet_Directory_Entry_Access;
   begin
      Manager.Root := Block;
      Manager.Next_Id := Wallet_Entry_Index'First;
      Next := Interfaces.Unsigned_32 (Block);
      while Next /= 0 loop
         Dir_Block := new Wallet_Directory_Entry;
         Dir_Block.Block := IO.Block_Number (Next);
         Manager.Entry_List.Append (Dir_Block);
         Load_Directory (Manager, Dir_Block, Stream);

         Next := Dir_Block.Next_Block;
      end loop;
   end Load_Complete_Directory;

   --  ------------------------------
   --  Find and load a directory block to hold a new entry that occupies the given space.
   --  The first directory block that has enough space is used otherwise a new block
   --  is allocated and initialized.
   --  ------------------------------
   procedure Find_Directory_Block (Manager     : in out Wallet_Manager;
                                   Space       : in IO.Block_Index;
                                   Entry_Block : out Wallet_Directory_Entry_Access;
                                   Stream      : in out IO.Wallet_Stream'Class) is
      Last_Block : Wallet_Directory_Entry_Access;
   begin
      --  Scan for a block having enough space for us.
      for Block of Manager.Entry_List loop
         if Block.Available >= Space then
            Block.Available := Block.Available - Space;
            Block.Count := Block.Count + 1;
            Entry_Block := Block;

            return;
         end if;
      end loop;

      --  We need a new wallet directory block.
      Entry_Block := new Wallet_Directory_Entry;
      Entry_Block.Available := IO.Block_Index'Last - IO.BT_DATA_START - Space - 4;
      Entry_Block.Count := 0;
      Entry_Block.Last_Pos := IO.BT_DATA_START + 4;
      Entry_Block.Ready := True;
      Stream.Allocate (Entry_Block.Block);

      Logs.Info (Log, "Adding directory block{0}", Entry_Block.Block);

      Last_Block := Manager.Entry_List.Last_Element;
      Manager.Entry_List.Append (Entry_Block);

      --  Update the last directory block to link to the new one.
      Load_Directory (Manager, Last_Block, Stream);
      Last_Block.Next_Block := Interfaces.Unsigned_32 (Entry_Block.Block);

      Manager.Buffer.Pos := IO.BT_DATA_START;
      IO.Put_Block_Number (Manager.Buffer, Entry_Block.Block);

      Keys.Set_IV (Manager.Config.Dir, Last_Block.Block);
      Stream.Write (Block  => Last_Block.Block,
                    From   => Manager.Buffer,
                    Cipher => Manager.Config.Dir.Cipher,
                    Sign   => Manager.Config.Dir.Sign);
   end Find_Directory_Block;

   --  ------------------------------
   --  Size of the wallet entry in the repository.
   --  ------------------------------
   function Entry_Size (Item : in Wallet_Entry_Access) return IO.Block_Index is
   begin
      return IO.SIZE_U32 + IO.SIZE_U16 + Item.Name'Length
        + IO.SIZE_DATE + IO.SIZE_BLOCK;
   end Entry_Size;

   --  ------------------------------
   --  Add a new entry in the wallet directory.
   --  ------------------------------
   procedure Add_Entry (Manager : in out Wallet_Manager;
                        Name    : in String;
                        Kind    : in Entry_Type;
                        Size    : in Interfaces.Unsigned_64;
                        Item    : out Wallet_Entry_Access;
                        Stream  : in out IO.Wallet_Stream'Class) is
      Space : constant IO.Block_Index := WALLET_ENTRY_SIZE + Name'Length;
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
      Item.Id := Manager.Next_Id;
      Manager.Next_Id := Manager.Next_Id + 1;

      --  Find and load the directory block that can hold the new entry.
      Find_Directory_Block (Manager, Space, Item.Header, Stream);

      --  Write the new entry at end of existing entries.
      Item.Entry_Offset := Item.Header.Last_Pos;

      --  Remember the last valid position for the next entry to add.
      Item.Header.Last_Pos := Item.Entry_Offset + Entry_Size (Item);

      --  Register it in the local repository.
      Manager.Map.Insert (Name, Item);
      Manager.Entry_Indexes.Insert (Item.Id, Item);

      Update_Entry (Manager, Item, Kind, Size, Stream);
   end Add_Entry;

   --  ------------------------------
   --  Update an existing entry in the wallet directory.
   --  ------------------------------
   procedure Update_Entry (Manager : in out Wallet_Manager;
                           Item    : in Wallet_Entry_Access;
                           Kind    : in Entry_Type;
                           Size    : in Interfaces.Unsigned_64;
                           Stream  : in out IO.Wallet_Stream'Class) is
   begin
      Item.Kind := Kind;
      Item.Size := Size;
      Item.Update_Date := Ada.Calendar.Clock;
      Item.Access_Date := Item.Update_Date;

      --  Allocate first data block.
      if Size > 0 and Item.Data = null then
         if Size < DATA_MAX_SIZE then
            Data.Allocate_Data_Block (Manager, IO.Block_Index (Size), Item.Data, Stream);
         else
            Data.Allocate_Data_Block (Manager, DATA_MAX_SIZE, Item.Data, Stream);
         end if;
      end if;

      if Item.Header.Count > 0 then
         --  Find and load the directory block that can hold the new entry.
         Load_Directory (Manager, Item.Header, Stream);
      else
         --  Prepare the new directory block.
         --  Fill the new block with random values or with zeros.
         if Manager.Randomize then
            Manager.Random.Generate (Manager.Buffer.Data);
         else
            Manager.Buffer.Data := (others => 0);
         end if;
         IO.Set_Header (Into => Manager.Buffer,
                        Tag  => IO.BT_WALLET_REPOSITORY,
                        Id   => Interfaces.Unsigned_32 (Manager.Id));
      end if;

      --  Write the new entry.
      Manager.Buffer.Pos := Item.Entry_Offset;
      IO.Put_Unsigned_32 (Manager.Buffer, Interfaces.Unsigned_32 (Item.Id));
      IO.Put_String (Manager.Buffer, Item.Name);
      IO.Put_Date (Manager.Buffer, Item.Create_Date);
      IO.Put_Block_Number (Manager.Buffer, Item.Data.Block);

      pragma Assert (Check => Manager.Buffer.Pos = Item.Entry_Offset + Entry_Size (Item));

      Keys.Set_IV (Manager.Config.Dir, Item.Header.Block);
      Stream.Write (Block  => Item.Header.Block,
                    From   => Manager.Buffer,
                    Cipher => Manager.Config.Dir.Cipher,
                    Sign   => Manager.Config.Dir.Sign);
   end Update_Entry;

   --  ------------------------------
   --  Delete the entry from the repository.
   --  ------------------------------
   procedure Delete_Entry (Manager    : in out Wallet_Manager;
                           Item       : in Wallet_Entry_Access;
                           Stream     : in out IO.Wallet_Stream'Class) is
      Dir_Block    : constant Wallet_Directory_Entry_Access := Item.Header;
      Wallet_Entry : Wallet_Entry_Access;
      Prev_Entry   : Wallet_Entry_Access;
      Size         : IO.Block_Index;
      End_Entry    : IO.Block_Index;
   begin
      Keystore.Logs.Debug (Log, "Delete entry from block{0}", Dir_Block.Block);

      Item.Header.Count := Item.Header.Count - 1;

      --  Load the directory block .
      Load_Directory (Manager, Item.Header, Stream);

      --  Unlink the item from the directory block list and identify the entry position.
      Wallet_Entry := Dir_Block.First;
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
         Dir_Block.First := Item.Next_Entry;
      end if;

      --  Move the data entry.
      Size := Entry_Size (Item);
      End_Entry := Item.Entry_Offset + Size;
      if End_Entry /= Dir_Block.Last_Pos then
         Manager.Buffer.Data (Item.Entry_Offset .. Dir_Block.Last_Pos - Size - 1)
           := Manager.Buffer.Data (End_Entry .. Dir_Block.Last_Pos - 1);
      end if;
      if Manager.Randomize then
         --  When strong security is necessary, fill with random values
         --  (except the first 4 bytes).
         Manager.Buffer.Data (Dir_Block.Last_Pos - Size .. Dir_Block.Last_Pos - Size + 3)
           := (others => 0);
         Manager.Random.Generate
           (Manager.Buffer.Data (Dir_Block.Last_Pos - Size + 4 .. Dir_Block.Last_Pos));
      else
         Manager.Buffer.Data (Dir_Block.Last_Pos - Size .. Dir_Block.Last_Pos) := (others => 0);
      end if;

      Dir_Block.Last_Pos := Dir_Block.Last_Pos - Size;

      Keys.Set_IV (Manager.Config.Dir, Dir_Block.Block);
      Stream.Write (Block        => Dir_Block.Block,
                    From         => Manager.Buffer,
                    Cipher       => Manager.Config.Dir.Cipher,
                    Sign         => Manager.Config.Dir.Sign);
   end Delete_Entry;

end Keystore.Repository.Entries;
