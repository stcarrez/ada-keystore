-----------------------------------------------------------------------
--  keystore-repository -- Repository management for the keystore
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

--  Block = 4K, 8K, 16K, 64K, 128K ?
--
--  Block types:
--  * Wallet File First Block
--  * Wallet Header
--  * Wallet Repository
--  * Wallet Data
--
--  Generic Block header
--  +------------------+
--  | Block HMAC-256   | 32b
--  +------------------+
--  | Block type       | 4b
--  | Wallet id        | 4b
--  | PAD 0            | 4b
--  | PAD 0            | 4b
--  +------------------+
--  | ...AES-CTR...    | B
--  +------------------+
--
--
--  Wallet repository encrypted with Wallet id AES-CTR key
--  +------------------+
--  | Block HMAC-256   | 32b
--  +------------------+
--  | 02 02 02 02      | 4b
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
--  Entry :      64
--  Entry-end:   16
--  Data:      3968   => 3%
package body Keystore.Repository is

   use type Interfaces.Unsigned_16;
   use type Interfaces.Unsigned_32;
   use type Interfaces.Unsigned_64;
   use type IO.Block_Count;

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Keystore.Repository");

   procedure Free is
     new Ada.Unchecked_Deallocation (Object => Wallet_Entry,
                                     Name   => Wallet_Entry_Access);

   procedure Free is
     new Ada.Unchecked_Deallocation (Object => Wallet_Block_Entry,
                                     Name   => Wallet_Block_Entry_Access);

   procedure Free is
     new Ada.Unchecked_Deallocation (Object => Wallet_Directory_Entry,
                                     Name   => Wallet_Directory_Entry_Access);

   --  Size of the wallet entry in the repository.
   function Entry_Size (Item : in Wallet_Entry_Access) return IO.Block_Index;

   function Hash (Value : in Wallet_Entry_Index) return Ada.Containers.Hash_Type is
   begin
      return Ada.Containers.Hash_Type (Value);
   end Hash;

   --  ------------------------------
   --  Set the key to encrypt and decrypt the container meta data.
   --  ------------------------------
   procedure Set_Key (Repository : in out Wallet_Repository;
                      Secret     : in Secret_Key) is
   begin
      Repository.Value.Set_Key (Secret);
   end Set_Key;

   --  Open the wallet repository by reading the meta data block header from the wallet
   --  IO stream.  The wallet meta data is decrypted using AES-CTR using the given secret
   --  key and initial vector.
   procedure Open (Repository : in out Wallet_Repository;
                   Password   : in Secret_Key;
                   Ident      : in Wallet_Identifier;
                   Block      : in Keystore.IO.Block_Number;
                   Keys       : in out Keystore.Keys.Key_Manager;
                   Stream     : in out IO.Wallet_Stream'Class) is
   begin
      if Repository.Is_Null then
         Refs.Ref (Repository) := Refs.Create;
      end if;
      Repository.Value.Open (Password, Ident, Block, Keys, Stream);
   end Open;

   procedure Open (Repository : in out Wallet_Repository;
                   Name       : in String;
                   Password   : in Secret_Key;
                   Wallet     : in out Wallet_Repository;
                   Stream     : in out IO.Wallet_Stream'Class) is
   begin
      if Wallet.Is_Null then
         Refs.Ref (Wallet) := Refs.Create;
      end if;
   end Open;

   procedure Create (Repository : in out Wallet_Repository;
                     Password   : in Secret_Key;
                     Block      : in IO.Block_Number;
                     Ident      : in Wallet_Identifier;
                     Keys       : in out Keystore.Keys.Key_Manager;
                     Stream     : in out IO.Wallet_Stream'Class) is
   begin
      if Repository.Is_Null then
         Refs.Ref (Repository) := Refs.Create;
      end if;
      Repository.Value.Create (Password, Ident, Block, Keys, Stream);
   end Create;

   procedure Add (Repository : in out Wallet_Repository;
                  Name       : in String;
                  Kind       : in Entry_Type;
                  Content    : in Ada.Streams.Stream_Element_Array;
                  Stream     : in out IO.Wallet_Stream'Class) is
   begin
      Repository.Value.Add (Name, Kind, Content, Stream);
   end Add;

   procedure Set (Repository : in out Wallet_Repository;
                  Name       : in String;
                  Kind       : in Entry_Type;
                  Content    : in Ada.Streams.Stream_Element_Array;
                  Stream     : in out IO.Wallet_Stream'Class) is
   begin
      Repository.Value.Set (Name, Kind, Content, Stream);
   end Set;

   procedure Set (Repository : in out Wallet_Repository;
                  Name       : in String;
                  Kind       : in Entry_Type;
                  Input      : in out Util.Streams.Input_Stream'Class;
                  Stream     : in out IO.Wallet_Stream'Class) is
   begin
      Repository.Value.Set (Name, Kind, Input, Stream);
   end Set;

   procedure Update (Repository : in out Wallet_Repository;
                     Name       : in String;
                     Kind       : in Entry_Type;
                     Content    : in Ada.Streams.Stream_Element_Array;
                     Stream     : in out IO.Wallet_Stream'Class) is
   begin
      Repository.Value.Update (Name, Kind, Content, Stream);
   end Update;

   procedure Add (Repository : in out Wallet_Repository;
                  Name       : in String;
                  Password   : in Secret_Key;
                  Wallet     : out Wallet_Repository'Class;
                  Stream     : in out IO.Wallet_Stream'Class) is
   begin
      Repository.Value.Add (Name, Password, Wallet, Stream);
   end Add;

   procedure Delete (Repository : in out Wallet_Repository;
                     Name       : in String;
                     Stream     : in out IO.Wallet_Stream'Class) is
   begin
      Repository.Value.Delete (Name, Stream);
   end Delete;

   function Contains (Repository : in Wallet_Repository;
                      Name       : in String) return Boolean is
   begin
      return Repository.Value.Contains (Name);
   end Contains;

   procedure Find (Repository : in Wallet_Repository;
                   Name       : in String;
                   Result     : out Entry_Info;
                   Stream     : in out IO.Wallet_Stream'Class) is
   begin
      Repository.Value.Find (Name, Result, Stream);
   end Find;

   procedure Get_Data (Repository : in out Wallet_Repository;
                       Name       : in String;
                       Result     : out Entry_Info;
                       Output     : out Ada.Streams.Stream_Element_Array;
                       Stream     : in out IO.Wallet_Stream'Class) is
   begin
      Repository.Value.Get_Data (Name, Result, Output, Stream);
   end Get_Data;

   procedure Write (Repository : in out Wallet_Repository;
                    Name       : in String;
                    Output     : in out Util.Streams.Output_Stream'Class;
                    Stream     : in out IO.Wallet_Stream'Class) is
   begin
      Repository.Value.Write (Name, Output, Stream);
   end Write;

   --  Get the list of entries contained in the wallet.
   procedure List (Repository : in out Wallet_Repository;
                   Content    : out Entry_Map;
                   Stream     : in out IO.Wallet_Stream'Class) is
   begin
      Repository.Value.List (Content, Stream);
   end List;

   procedure Close (Repository : in out Wallet_Repository) is
      Empty : Wallet_Repository;
   begin
      Repository.Value.Release;
      Repository := Empty;
   end Close;

   --  ------------------------------
   --  Set the IV vector to be used for the encryption of the given block number.
   --  ------------------------------
   procedure Set_IV (Manager : in out Wallet_Manager;
                     Block   : in IO.Block_Number) is
      Block_IV : Util.Encoders.AES.Word_Block_Type;
   begin
      Block_IV := Manager.IV;
      Block_IV (1) := Block_IV (1) xor Interfaces.Unsigned_32 (Block);
      Block_IV (4) := Block_IV (4) xor Interfaces.Unsigned_32 (Block);
      Manager.Decipher.Set_IV (Block_IV);
      Manager.Cipher.Set_IV (Block_IV);
   end Set_IV;

   --  ------------------------------
   --  Find the data block instance with the given block number.
   --  ------------------------------
   procedure Find_Data_Block (Manager    : in out Wallet_Manager;
                              Block      : in IO.Block_Number;
                              Data_Block : out Wallet_Block_Entry_Access) is
   begin
      for D of Manager.Data_List loop
         if D.Block = Block then
            Data_Block := D;
            Data_Block.Count := Data_Block.Count + 1;
            return;
         end if;
      end loop;
      Data_Block := new Wallet_Block_Entry;
      Data_Block.Available := IO.Block_Index'Last - IO.BT_DATA_START + 1;
      Data_Block.Count := 1;
      Data_Block.Block := Block;
      Data_Block.Last_Pos := IO.Block_Index'Last;
      Manager.Data_List.Append (Data_Block);
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

         Data.Load_Data (Manager, Candidate, Stream);
         Candidate := null;
      end loop;

      --  We need a new wallet directory block.
      Data_Block := new Wallet_Block_Entry;
      Data_Block.Available := IO.Block_Index'Last - IO.BT_DATA_START + 1;
      Data_Block.Count := 0;
      Data_Block.Last_Pos := IO.Block_Index'Last;
      Data_Block.Ready := True;
      Stream.Allocate (Data_Block.Block);
      Manager.Data_List.Append (Data_Block);

      Logs.Debug (Log, "Allocated data block{0}", Data_Block.Block);
   end Allocate_Data_Block;

   --  ------------------------------
   --  Release the data block to the stream.
   --  ------------------------------
   procedure Release_Data_Block (Manager    : in out Wallet_Manager;
                                 Data_Block : in out Wallet_Block_Entry_Access;
                                 Stream     : in out IO.Wallet_Stream'Class) is
      Pos : Wallet_Block_List.Cursor := Manager.Data_List.Find (Data_Block);
   begin
      Manager.Data_List.Delete (Pos);
      Stream.Release (Block => Data_Block.Block);
      Free (Data_Block);
   end Release_Data_Block;

   --  ------------------------------
   --  Initialize the data block with an empty content.
   --  ------------------------------
   procedure Init_Data_Block (Manager    : in out Wallet_Manager) is
   begin
      --  Prepare the new data block.
      Manager.Buffer.Data := (others => 0);
      IO.Set_Header (Into => Manager.Buffer,
                     Tag  => IO.BT_WALLET_DATA,
                     Id   => Interfaces.Unsigned_32 (Manager.Id));
   end Init_Data_Block;

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
      Set_IV (Manager, Dir_Block.Block);
      Stream.Read (Block        => Dir_Block.Block,
                   Decipher     => Manager.Decipher,
                   Sign         => Manager.Sign,
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
                  Find_Data_Block (Manager, IO.Get_Block_Number (Manager.Buffer), Item.Data);

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

      Set_IV (Manager, Last_Block.Block);
      Stream.Write (Block  => Last_Block.Block,
                    From   => Manager.Buffer,
                    Cipher => Manager.Cipher,
                    Sign   => Manager.Sign);
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
            Allocate_Data_Block (Manager, IO.Block_Index (Size), Item.Data, Stream);
         else
            Allocate_Data_Block (Manager, DATA_MAX_SIZE, Item.Data, Stream);
         end if;
      end if;

      if Item.Header.Count > 0 then
         --  Find and load the directory block that can hold the new entry.
         Load_Directory (Manager, Item.Header, Stream);
      else
         --  Prepare the new directory block.
         Manager.Buffer.Data := (others => 0);
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

      Set_IV (Manager, Item.Header.Block);
      Stream.Write (Block  => Item.Header.Block,
                    From   => Manager.Buffer,
                    Cipher => Manager.Cipher,
                    Sign   => Manager.Sign);
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
      Manager.Buffer.Data (Dir_Block.Last_Pos - Size .. Dir_Block.Last_Pos) := (others => 0);

      Dir_Block.Last_Pos := Dir_Block.Last_Pos - Size;

      Set_IV (Manager, Dir_Block.Block);
      Stream.Write (Block        => Dir_Block.Block,
                    From         => Manager.Buffer,
                    Cipher       => Manager.Cipher,
                    Sign         => Manager.Sign);
   end Delete_Entry;

   procedure Update (Manager    : in out Wallet_Manager;
                     Name       : in String;
                     Kind       : in Entry_Type;
                     Content    : in Ada.Streams.Stream_Element_Array;
                     Stream     : in out IO.Wallet_Stream'Class) is
      Pos          : constant Wallet_Maps.Cursor := Manager.Map.Find (Name);
      Item         : Wallet_Entry_Access;
      Start        : Stream_Element_Offset := Content'First;
      Data_Block   : Wallet_Block_Entry_Access;
      New_Block    : Wallet_Block_Entry_Access;
      Delete_Block : Wallet_Block_Entry_Access;
      Data_Offset  : Ada.Streams.Stream_Element_Offset := 0;
   begin
      Log.Debug ("Update keystore entry {0}", Name);

      if not Wallet_Maps.Has_Element (Pos) then
         Log.Info ("Data entry '{0}' not found", Name);
         raise Not_Found;
      end if;

      Item := Wallet_Maps.Element (Pos);

      --  If there is enough room in the current data block, use it.
      Data_Block := Item.Data;

      Item.Kind := Kind;
      Data.Update_Data (Manager, Item, Data_Block, Content,
                        Data_Offset, True, New_Block, Delete_Block, Stream);

      --  Write the data in one or several blocks.
      if New_Block /= null then
         Start := Content'First + Data_Offset;
         Data.Add_Data (Manager, Item, New_Block, Content (Start .. Content'Last),
                        Data_Offset, False, Stream);
      end if;

      if Delete_Block /= null then
         Data.Delete_Data (Manager, Item, Delete_Block, Stream);
      end if;

      Update_Entry (Manager, Item, Kind, Content'Length, Stream);
   end Update;

   procedure Update (Manager    : in out Wallet_Manager;
                     Name       : in String;
                     Kind       : in Entry_Type;
                     Input      : in out Util.Streams.Input_Stream'Class;
                     Stream     : in out IO.Wallet_Stream'Class) is
      Item_Pos     : constant Wallet_Maps.Cursor := Manager.Map.Find (Name);
      Item         : Wallet_Entry_Access;
      Data_Block   : Wallet_Block_Entry_Access;
      New_Block    : Wallet_Block_Entry_Access;
      Delete_Block : Wallet_Block_Entry_Access;
      Pos          : Ada.Streams.Stream_Element_Offset;
      Last         : Ada.Streams.Stream_Element_Offset;
      Old_Offset   : Ada.Streams.Stream_Element_Offset;
      Data_Offset  : Ada.Streams.Stream_Element_Offset := 0;
      Content      : Stream_Element_Array (1 .. 4 * 4096);
      Remain       : Stream_Element_Offset;
   begin
      Log.Debug ("Update keystore entry {0}", Name);

      if not Wallet_Maps.Has_Element (Item_Pos) then
         Log.Info ("Data entry '{0}' not found", Name);
         raise Not_Found;
      end if;

      Item := Wallet_Maps.Element (Item_Pos);

      --  If there is enough room in the current data block, use it.
      Data_Block := Item.Data;

      Item.Kind := Kind;
      Pos := Content'First;
      loop
         while Pos < Content'Last loop
            Input.Read (Content (Pos .. Content'Last), Last);
            exit when Last < Pos;
            Pos := Last + 1;
         end loop;

         Old_Offset := Data_Offset;
         if New_Block = null then
            if Last < Content'Last then
               Data.Update_Data (Manager, Item, Data_Block, Content (Content'First .. Last),
                                 Data_Offset, False, New_Block, Delete_Block, Stream);
               exit when New_Block = null;
            else
               Data.Update_Data (Manager, Item, Data_Block, Content,
                                 Data_Offset, True, New_Block, Delete_Block, Stream);
            end if;
         else
            if Last < Content'Last then
               Data.Add_Data (Manager, Item, New_Block, Content (Content'First .. Last),
                              Data_Offset, False, Stream);
               exit;
            else
               --  Write the data in one or several blocks.
               Data.Add_Data (Manager, Item, New_Block, Content,
                              Data_Offset, True, Stream);
            end if;
         end if;
         Remain := (Last - Content'First + 1) - (Data_Offset - Old_Offset);
         Pos := Content'First + Remain;
         if Remain > 0 then
            Content (Content'First .. Content'First + Remain - 1)
              := Content (Last - Remain + 1 .. Last);
         end if;
      end loop;

      if Delete_Block /= null then
         Data.Delete_Data (Manager, Item, Delete_Block, Stream);
      end if;

      Update_Entry (Manager, Item, Kind, Interfaces.Unsigned_64 (Data_Offset), Stream);
   end Update;

   procedure Add (Manager    : in out Wallet_Manager;
                  Name       : in String;
                  Kind       : in Entry_Type;
                  Content    : in Ada.Streams.Stream_Element_Array;
                  Stream     : in out IO.Wallet_Stream'Class) is
      Item        : Wallet_Entry_Access;
      Data_Offset : Stream_Element_Offset := 0;
   begin
      Add_Entry (Manager, Name, Kind, Content'Length, Item, Stream);

      if Content'Length = 0 then
         return;
      end if;

      Data.Add_Data (Manager, Item, Item.Data, Content, Data_Offset, False, Stream);
   end Add;

   --  ------------------------------
   --  Delete the value associated with the given name.
   --  Raises the Not_Found exception if the name was not found.
   --  ------------------------------
   procedure Delete (Manager    : in out Wallet_Manager;
                     Name       : in String;
                     Stream     : in out IO.Wallet_Stream'Class) is
      Pos        : Wallet_Maps.Cursor := Manager.Map.Find (Name);
      Item       : Wallet_Entry_Access;
      Block      : Wallet_Block_Entry_Access;
      Next_Block : Wallet_Block_Entry_Access;
   begin
      if not Wallet_Maps.Has_Element (Pos) then
         Log.Info ("Data entry '{0}' not found", Name);
         raise Not_Found;
      end if;

      Item := Wallet_Maps.Element (Pos);
      begin
         --  Erase the data fragments used by the entry.
         Block := Item.Data;
         while Block /= null loop
            Data.Load_Data (Manager, Block, Stream);
            Data.Delete_Fragment (Manager    => Manager,
                                  Data_Block => Block.all,
                                  Next_Block => Next_Block,
                                  Item       => Item);
            if Block.Count = 0 then
               Release_Data_Block (Manager, Block, Stream);
            else
               Data.Save_Data (Manager, Block.all, Stream);
            end if;
            Block := Next_Block;
         end loop;

         --  Erase the entry from the repository.
         Delete_Entry (Manager => Manager,
                       Item    => Item,
                       Stream  => Stream);
      exception
         when others =>
            --  Handle data or directory block corruption or IO error.
            Manager.Entry_Indexes.Delete (Item.Id);
            Manager.Map.Delete (Pos);
            Free (Item);
            raise;
      end;
      Manager.Entry_Indexes.Delete (Item.Id);
      Manager.Map.Delete (Pos);
      Free (Item);
   end Delete;

   procedure Write (Manager    : in out Wallet_Manager;
                    Name       : in String;
                    Output     : in out Util.Streams.Output_Stream'Class;
                    Stream     : in out IO.Wallet_Stream'Class) is
      Pos         : constant Wallet_Maps.Cursor := Manager.Map.Find (Name);
      Item        : Wallet_Entry_Access;
      Data_Block  : Wallet_Block_Entry_Access;
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
         Data.Load_Data (Manager, Data_Block, Stream);
         Position := Get_Fragment_Position (Data_Block.all, Item);
         exit when Position = 0;
         Data.Get_Fragment (Manager, Position, Data_Block.Fragments (Position), Output);
         Data_Block := Data_Block.Fragments (Position).Next_Fragment;
      end loop;
   end Write;

   procedure Release (Manager    : in out Wallet_Manager) is
      Dir   : Wallet_Directory_Entry_Access;
      Block : Wallet_Block_Entry_Access;
      First : Wallet_Maps.Cursor;
      Item  : Wallet_Entry_Access;
   begin
      while not Manager.Entry_List.Is_Empty loop
         Dir := Manager.Entry_List.First_Element;
         Manager.Entry_List.Delete_First;
         Free (Dir);
      end loop;
      while not Manager.Data_List.Is_Empty loop
         Block := Manager.Data_List.First_Element;
         Manager.Data_List.Delete_First;
         Free (Block);
      end loop;

      Manager.Entry_Indexes.Clear;
      while not Manager.Map.Is_Empty loop
         First := Manager.Map.First;
         Item := Wallet_Maps.Element (First);
         Free (Item);
         Manager.Map.Delete (First);
      end loop;
   end Release;

   protected body Safe_Wallet_Repository is

      procedure Set_Key (Secret     : in Secret_Key) is
      begin
         Manager.Decipher.Set_Key (Secret);
         Manager.Cipher.Set_Key (Secret);
      end Set_Key;

      --  Open the wallet repository by reading the meta data block header from the wallet
      --  IO stream.  The wallet meta data is decrypted using AES-CTR using the given secret
      --  key and initial vector.
      procedure Open (Password     : in Secret_Key;
                      Ident        : in Wallet_Identifier;
                      Block        : in Keystore.IO.Block_Number;
                      Keys         : in out Keystore.Keys.Key_Manager;
                      Stream       : in out IO.Wallet_Stream'Class) is
      begin
         Manager.Id := Ident;
         Keys.Open (Password, Ident, Block, Manager.Root, Manager.Protect_Key,
                    Manager.IV, Manager.Cipher, Manager.Decipher, Stream);

         Load_Complete_Directory (Manager, Manager.Root, Stream);
      end Open;

      procedure Create (Password : in Secret_Key;
                        Ident    : in Wallet_Identifier;
                        Block    : in IO.Block_Number;
                        Keys     : in out Keystore.Keys.Key_Manager;
                        Stream   : in out IO.Wallet_Stream'Class) is
         Entry_Block : Wallet_Directory_Entry_Access;
      begin
         Stream.Allocate (Manager.Root);
         Manager.Id := Ident;
         Manager.Next_Id := 1;
         Keys.Create (Password, 1, Ident, Block, Manager.Root, Manager.Protect_Key,
                      Manager.IV, Manager.Cipher, Manager.Decipher, Stream);

         --  We need a new wallet directory block.
         Entry_Block := new Wallet_Directory_Entry;
         Entry_Block.Available := IO.Block_Index'Last - IO.BT_DATA_START - 4;
         Entry_Block.Count := 0;
         Entry_Block.Last_Pos := IO.BT_DATA_START + 4;
         Entry_Block.Ready := True;
         Entry_Block.Block := Manager.Root;
         Manager.Entry_List.Append (Entry_Block);

         Manager.Buffer.Data := (others => 0);
         IO.Set_Header (Into => Manager.Buffer,
                        Tag  => IO.BT_WALLET_REPOSITORY,
                        Id   => Interfaces.Unsigned_32 (Manager.Id));
         Set_IV (Manager, Manager.Root);
         Stream.Write (Block  => Manager.Root,
                       From   => Manager.Buffer,
                       Cipher => Manager.Cipher,
                       Sign   => Manager.Sign);
      end Create;

      procedure Add (Name     : in String;
                     Password : in Secret_Key;
                     Wallet   : out Wallet_Repository'Class;
                     Stream   : in out IO.Wallet_Stream'Class) is
         Repo      : constant Safe_Wallet_Repository_Access := Wallet.Value;
         Item      : Wallet_Entry_Access;
         Keys      : Keystore.Keys.Key_Manager;
      begin
         Add_Entry (Manager, Name, T_WALLET, 0, Item, Stream);

         Stream.Allocate (Item.Block);

         --  Keys.Set_Header_Key
         Repo.Create (Password, 1, IO.Block_Number (Item.Block), Keys, Stream);
      end Add;

      procedure Add (Name       : in String;
                     Kind       : in Entry_Type;
                     Content    : in Ada.Streams.Stream_Element_Array;
                     Stream     : in out IO.Wallet_Stream'Class) is
         Item        : Wallet_Entry_Access;
         Data_Offset : Stream_Element_Offset := 0;
      begin
         Add_Entry (Manager, Name, Kind, Content'Length, Item, Stream);

         if Content'Length = 0 then
            return;
         end if;

         Data.Add_Data (Manager, Item, Item.Data, Content, Data_Offset, False, Stream);
      end Add;

      procedure Add (Name       : in String;
                     Kind       : in Entry_Type;
                     Input      : in out Util.Streams.Input_Stream'Class;
                     Stream     : in out IO.Wallet_Stream'Class) is
         Item        : Wallet_Entry_Access;
         Content     : Ada.Streams.Stream_Element_Array (1 .. 4 * 4096);
         Last        : Stream_Element_Offset;
         Data_Offset : Stream_Element_Offset := 0;
         Old_Offset  : Stream_Element_Offset;
         Pos         : Stream_Element_Offset;
         Remain      : Stream_Element_Offset;
         Block       : Wallet_Block_Entry_Access;
      begin
         Pos := Content'First;
         loop
            while Pos < Content'Last loop
               Input.Read (Content (Pos .. Content'Last), Last);
               exit when Last < Pos;
               Pos := Last + 1;
            end loop;

            if Item = null then
               Add_Entry (Manager, Name, Kind, Interfaces.Unsigned_64 (Last - Content'First + 1),
                          Item, Stream);

               Block := Item.Data;
            end if;

            if Last < Content'Last then
               Data.Add_Data (Manager, Item, Block, Content (Content'First .. Last),
                              Data_Offset, False, Stream);
               return;
            else
               Old_Offset := Data_Offset;
               Data.Add_Data (Manager, Item, Block, Content, Data_Offset, True, Stream);
               Remain := Content'Length - (Data_Offset - Old_Offset + 1);
               Pos := Content'First + Remain;
               if Remain > 0 then
                  Content (Content'First .. Content'First + Remain - 1)
                    := Content (Content'Last - Remain + 1 .. Content'Last);
               end if;
            end if;
         end loop;
      end Add;

      procedure Set (Name       : in String;
                     Kind       : in Entry_Type;
                     Content    : in Ada.Streams.Stream_Element_Array;
                     Stream     : in out IO.Wallet_Stream'Class) is
      begin
         if Manager.Map.Contains (Name) then
            Update (Manager, Name, Kind, Content, Stream);
         else
            Add (Manager, Name, Kind, Content, Stream);
         end if;
      end Set;

      procedure Set (Name       : in String;
                     Kind       : in Entry_Type;
                     Input      : in out Util.Streams.Input_Stream'Class;
                     Stream     : in out IO.Wallet_Stream'Class) is
      begin
         if Manager.Map.Contains (Name) then
            Update (Name, Kind, Input, Stream);
         else
            Add (Name, Kind, Input, Stream);
         end if;
      end Set;

      procedure Update (Name       : in String;
                        Kind       : in Entry_Type;
                        Content    : in Ada.Streams.Stream_Element_Array;
                        Stream     : in out IO.Wallet_Stream'Class) is
      begin
         Update (Manager, Name, Kind, Content, Stream);
      end Update;

      procedure Update (Name       : in String;
                        Kind       : in Entry_Type;
                        Input      : in out Util.Streams.Input_Stream'Class;
                        Stream     : in out IO.Wallet_Stream'Class) is
      begin
         Update (Manager, Name, Kind, Input, Stream);
      end Update;

      procedure Delete (Name       : in String;
                        Stream     : in out IO.Wallet_Stream'Class) is
      begin
         Delete (Manager, Name, Stream);
      end Delete;

      function Contains (Name : in String) return Boolean is
      begin
         return Manager.Map.Contains (Name);
      end Contains;

      procedure Find (Name       : in String;
                      Result     : out Entry_Info;
                      Stream     : in out IO.Wallet_Stream'Class) is
         Pos  : constant Wallet_Maps.Cursor := Manager.Map.Find (Name);
         Item : Wallet_Entry_Access;
      begin
         if not Wallet_Maps.Has_Element (Pos) then
            Log.Info ("Data entry '{0}' not found", Name);
            raise Not_Found;
         end if;

         Item := Wallet_Maps.Element (Pos);
         if Item.Kind = T_INVALID then
            Data.Load_Data (Manager, Item.Data, Stream);
            if Item.Kind = T_INVALID then
               Log.Error ("Wallet entry {0} is corrupted", Name);
               raise Corrupted;
            end if;
         end if;
         Result.Size := Natural (Item.Size);
         Result.Kind := Item.Kind;
         Result.Create_Date := Item.Create_Date;
         Result.Update_Date := Item.Update_Date;
      end Find;

      procedure Get_Data (Name       : in String;
                          Result     : out Entry_Info;
                          Output     : out Ada.Streams.Stream_Element_Array;
                          Stream     : in out IO.Wallet_Stream'Class) is
      begin
         Data.Get_Data (Manager, Name, Result, Output, Stream);
      end Get_Data;

      procedure Write (Name       : in String;
                       Output     : in out Util.Streams.Output_Stream'Class;
                       Stream     : in out IO.Wallet_Stream'Class) is
      begin
         Write (Manager, Name, Output, Stream);
      end Write;

      procedure List (Content    : out Entry_Map;
                      Stream     : in out IO.Wallet_Stream'Class) is
         Value : Entry_Info;
      begin
         for Item of Manager.Map loop
            if Item.Kind = T_INVALID then
               Data.Load_Data (Manager, Item.Data, Stream);
            end if;
            Value.Size := Integer (Item.Size);
            Value.Kind := Item.Kind;
            Value.Create_Date := Item.Create_Date;
            Value.Update_Date := Item.Update_Date;
            Content.Include (Key      => Item.Name,
                             New_Item => Value);
         end loop;
      end List;

      procedure Release is
      begin
         Release (Manager);
      end Release;

   end Safe_Wallet_Repository;

end Keystore.Repository;
