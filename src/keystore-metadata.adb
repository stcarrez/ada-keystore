-----------------------------------------------------------------------
--  keystore-files -- Ada keystore files
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
package body Keystore.Metadata is

   use type Interfaces.Unsigned_16;
   use type Interfaces.Unsigned_32;
   use type Interfaces.Unsigned_64;
   use type IO.Block_Count;

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Keystore.Metadata");

   procedure Free is
     new Ada.Unchecked_Deallocation (Object => Wallet_Entry,
                                     Name   => Wallet_Entry_Access);

   procedure Free is
     new Ada.Unchecked_Deallocation (Object => Wallet_Block_Entry,
                                     Name   => Wallet_Block_Entry_Access);

   --  Start offset of the data entry descriptor in the data block.
   function Data_Entry_Offset (Index : in Fragment_Index) return IO.Block_Index;

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

   procedure Find (Repository : in out Wallet_Repository;
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
      Data_Block.Available := IO.Block_Index'Last - IO.BT_DATA_START;
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
            if Block.Available >= Space then
               if Block.Ready then
                  Data_Block := Block;
                  return;
               end if;
               Candidate := Block;
            end if;
         end loop;

         exit when Candidate = null;

         Load_Data (Manager, Candidate, Stream);
         Candidate := null;
      end loop;

      --  We need a new wallet directory block.
      Data_Block := new Wallet_Block_Entry;
      Data_Block.Available := IO.Block_Index'Last - IO.BT_DATA_START;
      Data_Block.Count := 0;
      Data_Block.Last_Pos := IO.Block_Index'Last;
      Data_Block.Ready := True;
      Stream.Allocate (Data_Block.Block);
      Manager.Data_List.Append (Data_Block);
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
                             Dir_Block : in Wallet_Block_Entry_Access;
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
      Dir_Block : Wallet_Block_Entry_Access;
   begin
      Manager.Root := Block;
      Manager.Next_Id := Wallet_Entry_Index'First;
      Next := Interfaces.Unsigned_32 (Block);
      while Next /= 0 loop
         Dir_Block := new Wallet_Block_Entry;
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
                                   Entry_Block : out Wallet_Block_Entry_Access;
                                   Stream      : in out IO.Wallet_Stream'Class) is
   begin
      --  Scan for a block having enough space for us.
      for Block of Manager.Entry_List loop
         if Block.Available >= Space then
            Block.Available := Block.Available - Space;
            Block.Count := Block.Count + 1;
            Entry_Block := Block;

            --  Load the directory block to write the new entry.
            Load_Directory (Manager, Entry_Block, Stream);

            return;
         end if;
      end loop;

      --  We need a new wallet directory block.
      Entry_Block := new Wallet_Block_Entry;
      Entry_Block.Available := IO.Block_Index'Last - IO.BT_DATA_START - Space - 4;
      Entry_Block.Count := 0;
      Entry_Block.Last_Pos := IO.BT_DATA_START + 4;
      Entry_Block.Ready := True;
      Stream.Allocate (Entry_Block.Block);
      Manager.Entry_List.Append (Entry_Block);

      --  Prepare the new directory block.
      Manager.Buffer.Data := (others => 0);
      IO.Set_Header (Into => Manager.Buffer,
                     Tag  => IO.BT_WALLET_REPOSITORY,
                     Id   => Interfaces.Unsigned_32 (Manager.Id));

   end Find_Directory_Block;

   --  ------------------------------
   --  Load the data block in the wallet manager buffer.  Extract the data descriptors
   --  the first time the data block is read.
   --  ------------------------------
   procedure Load_Data (Manager    : in out Wallet_Manager;
                        Data_Block : in Wallet_Block_Entry_Access;
                        Stream     : in out IO.Wallet_Stream'Class) is
      --  We only decrypt the data entry descriptors.
      --  Size  : constant IO.Block_Index := IO.Block_Index (Data_Block.Count * DATA_ENTRY_SIZE);
      Btype : Interfaces.Unsigned_16;
      Wid   : Interfaces.Unsigned_32;
      Size  : IO.Block_Index;
   begin
      --  Logs.Debug (Log, "Load data block{0} decrypt{1}", Data_Block.Block, Size);

      --  Read wallet data block.
      Set_IV (Manager, Data_Block.Block);
      Stream.Read (Block        => Data_Block.Block,
                   Decipher     => Manager.Decipher,
                   Sign         => Manager.Sign,
                   Decrypt_Size => Size,
                   Into         => Manager.Buffer);

      --  Check block type.
      Btype := IO.Get_Unsigned_16 (Manager.Buffer);
      if Btype /= IO.BT_WALLET_DATA then
         Logs.Error (Log, "Block{0} invalid block type", Data_Block.Block);
         raise Keystore.Corrupted;
      end if;
      IO.Skip (Manager.Buffer, 2);

      --  Check that this is a block for the current wallet.
      Wid := IO.Get_Unsigned_32 (Manager.Buffer);
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
            IO.Skip (Manager.Buffer, 8);

            while Manager.Buffer.Pos < IO.BT_DATA_START + Size loop
               Frag := Frag + 1;

               pragma Assert (Check => Manager.Buffer.Pos = Data_Entry_Offset (Frag));

               Index := IO.Get_Unsigned_32 (Manager.Buffer);
               exit when Index = 0;
               Pos := Manager.Entry_Indexes.Find (Wallet_Entry_Index (Index));
               if Wallet_Indexs.Has_Element (Pos) then
                  Item := Wallet_Indexs.Element (Pos);
                  Item.Kind := IO.Get_Kind (Manager.Buffer);
                  Slot_Size := IO.Get_Unsigned_16 (Manager.Buffer);
                  Item_Size := IO.Get_Unsigned_64 (Manager.Buffer);
                  Item.Size := Item_Size;
                  Next_Block := null;
                  if Item_Size = Interfaces.Unsigned_64 (Slot_Size) then
                     Item.Update_Date := IO.Get_Date (Manager.Buffer);
                     Item.Access_Date := IO.Get_Date (Manager.Buffer);
                     Data_Offset := 0;
                  else
                     Item.Access_Date := IO.Get_Date (Manager.Buffer);
                     Block := IO.Get_Block_Number (Manager.Buffer);
                     if Block /= 0 then
                        Find_Data_Block (Manager, Block, Next_Block);
                     end if;
                     Data_Offset := IO.Get_Unsigned_32 (Manager.Buffer);
                  end if;

                  --  Skip the IV, Key, HMAC-256
                  IO.Skip (Manager.Buffer, IO.SIZE_HMAC + IO.SIZE_SECRET + IO.SIZE_IV);

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
   --  Size of the wallet entry in the repository.
   --  ------------------------------
   function Entry_Size (Item : in Wallet_Entry_Access) return IO.Block_Index is
   begin
      return IO.SIZE_U32 + IO.SIZE_U16 + Item.Name'Length
        + IO.SIZE_DATE + IO.SIZE_BLOCK;
   end Entry_Size;

   --  ------------------------------
   --  Save the data block.
   --  ------------------------------
   procedure Save_Data (Manager    : in out Wallet_Manager;
                        Data_Block : in out Wallet_Block_Entry;
                        Stream     : in out IO.Wallet_Stream'Class) is
      Encrypt_Size  : IO.Block_Index;
   begin
      Encrypt_Size := IO.Block_Index (Data_Block.Count * DATA_ENTRY_SIZE);

      Keystore.Logs.Debug (Log, "Save data block{0} encrypt{1}", Data_Block.Block, Encrypt_Size);

      Set_IV (Manager, Data_Block.Block);
      Stream.Write (Block        => Data_Block.Block,
                    From         => Manager.Buffer,
                    Encrypt_Size => Encrypt_Size,
                    Cipher       => Manager.Cipher,
                    Sign         => Manager.Sign);
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
                           Data_Block  : in Wallet_Block_Entry_Access;
                           Item        : in Wallet_Entry_Access;
                           Data_Offset : in Ada.Streams.Stream_Element_Offset;
                           Next_Block  : in Wallet_Block_Entry_Access;
                           Content     : in Ada.Streams.Stream_Element_Array) is
      Data_Size     : constant IO.Block_Index := AES_Align (Content'Length);
      Cipher_Data   : Util.Encoders.AES.Encoder;
      IV            : Util.Encoders.AES.Word_Block_Type;
      Secret        : Keystore.Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      Salt          : Ada.Streams.Stream_Element_Array (1 .. 32);
      Start_Data    : IO.Block_Index;
      End_Data      : IO.Block_Index;
      Last_Encoded  : Ada.Streams.Stream_Element_Offset;
      Last_Pos      : Ada.Streams.Stream_Element_Offset;
   begin
      --  Generate a key and IV for the data fragment.
      Manager.Random.Generate (Salt);
      Manager.Random.Generate (IV);
      Util.Encoders.Create (Salt, Secret);

      Data_Block.Count := Data_Block.Count + 1;

      --  Serialize the data entry at end of data entry area.
      Manager.Buffer.Pos := Data_Entry_Offset (Data_Block.Count);
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

      IO.Put_Data (Manager.Buffer, IV);
      IO.Put_Secret (Manager.Buffer, Secret, Manager.Protect_Key);

      --  Make HMAC-SHA256 signature of the data content before encryption.
      IO.Put_HMAC_SHA256 (Manager.Buffer, Manager.Sign, Content);

      Data_Block.Available := Data_Block.Available - Data_Size - DATA_ENTRY_SIZE;
      Data_Block.Last_Pos := Data_Block.Last_Pos - Data_Size;

      --  Record the fragment in the data block.
      Data_Block.Fragments (Data_Block.Count).Item := Item;
      Data_Block.Fragments (Data_Block.Count).Data_Offset := Data_Offset;
      Data_Block.Fragments (Data_Block.Count).Size := Content'Length;
      Data_Block.Fragments (Data_Block.Count).Next_Fragment := Next_Block;
      Data_Block.Fragments (Data_Block.Count).Block_Offset := Data_Block.Last_Pos;
      if Item.Data = null then
         Item.Data := Data_Block;
      end if;

      Start_Data := Data_Block.Last_Pos;
      End_Data := Start_Data + Data_Size - 1;

      pragma Assert (Check => Manager.Buffer.Pos = Data_Entry_Offset (Data_Block.Count + 1));
      pragma Assert (Check => Data_Block.Last_Pos > Data_Entry_Offset (Data_Block.Count + 1));

      --  Encrypt the data content using the item encryption key and IV.
      Cipher_Data.Set_IV (IV);
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
      IV            : Util.Encoders.AES.Word_Block_Type;
      Secret        : Keystore.Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      Salt          : Ada.Streams.Stream_Element_Array (1 .. 32);
      Start_Data    : IO.Block_Index;
      End_Data      : IO.Block_Index;
      Last_Encoded  : Ada.Streams.Stream_Element_Offset;
      Last_Pos      : Ada.Streams.Stream_Element_Offset;
   begin
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

      IO.Get_Data (Manager.Buffer, IV);
      IO.Get_Secret (Manager.Buffer, Secret, Manager.Protect_Key);

      --  IO.Put_Data (Manager.Buffer, IV);
      --  IO.Put_Secret (Manager.Buffer, Secret, Manager.Protect_Key);

      --  Make HMAC-SHA256 signature of the data content before encryption.
      IO.Put_HMAC_SHA256 (Manager.Buffer, Manager.Sign, Content);

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
            Data_Block.Last_Pos := Data_Block.Last_Pos + Offset;
         end if;
      end if;

      --  Encrypt the data content using the item encryption key and IV.
      Cipher_Data.Set_IV (IV);
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
                           Item     : in Wallet_Entry_Access;
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
      IV         : Util.Encoders.AES.Word_Block_Type;
   begin
      Manager.Buffer.Pos := Data_Entry_Offset (Position) + DATA_IV_OFFSET;
      IO.Get_Data (Manager.Buffer, IV);
      IO.Get_Secret (Manager.Buffer, Secret, Manager.Protect_Key);

      Decipher.Set_IV (IV);
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
         raise Name_Exist;
      end if;

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

      --  Find and load the directory block that can hold the new entry.
      Load_Directory (Manager, Item.Header, Stream);

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
      Dir_Block    : constant Wallet_Block_Entry_Access := Item.Header;
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
      Loaded : Boolean := False;
      Start        : Stream_Element_Offset := Content'First;
      Last         : Stream_Element_Offset;
      Space        : Stream_Element_Offset;
      Data_Block   : Wallet_Block_Entry_Access;
      Next_Block   : Wallet_Block_Entry_Access;
      New_Block    : Wallet_Block_Entry_Access;
      Delete_Block : Wallet_Block_Entry_Access;
      Data_Offset  : Ada.Streams.Stream_Element_Offset := Content'First;
      Position     : Fragment_Count;
   begin
      Log.Debug ("Update keystore entry {0}", Name);

      if not Wallet_Maps.Has_Element (Pos) then
         Log.Info ("Data entry '{0}' not found", Name);
         raise Not_Found;
      end if;

      Item := Wallet_Maps.Element (Pos);

      --  If there is enough room in the current data block, use it.
      Data_Block := Item.Data;

      --  Update the data fragments.
      while Data_Block /= null loop
         Load_Data (Manager, Data_Block, Stream);
         Item.Kind := Kind;
         Item.Size := Content'Length;
         Position := Get_Fragment_Position (Data_Block.all, Item);
         exit when Position = 0;

         --  See how much space we have in the current block.
         Space := Data_Block.Available - AES_Align (Data_Block.Fragments (Position).Size);
         if Space >= AES_Align (Content'Length - Data_Offset) then
            Last := Content'Last;
            Delete_Block := Data_Block.Fragments (Position).Next_Fragment;
            Next_Block := null;
         else
            Last := Data_Offset + Space - 1;
            Next_Block := Data_Block.Fragments (Position).Next_Fragment;
            if Next_Block = null and Last < Content'Last then
               Allocate_Data_Block (Manager, DATA_MAX_SIZE, New_Block, Stream);
               Next_Block := null;
            end if;
         end if;

         Update_Fragment (Manager, Data_Block, Item, Data_Offset, Position,
                          Data_Block.Fragments (Position),
                          Next_Block, Content (Data_Offset .. Last));
         Data_Offset := Data_Offset + Data_Block.Fragments (Position).Size;

         Save_Data (Manager, Data_Block.all, Stream);
         Data_Block := Next_Block;
         exit when Data_Offset > Content'Last;
      end loop;

      --  Write the data in one or several blocks.
      while New_Block /= null loop
         if Content'Last - Start + 1 > DATA_MAX_SIZE then
            Last := Start + DATA_MAX_SIZE - 1;
            Allocate_Data_Block (Manager, DATA_MAX_SIZE, Next_Block, Stream);
         else
            Last := Content'Last;
            Next_Block := null;
         end if;

         Add_Fragment (Manager, New_Block, Item, Data_Offset,
                       Next_Block, Content (Start .. Last));
         Save_Data (Manager, New_Block.all, Stream);
         Data_Offset := Data_Offset + Last - Start + 1;
         Start := Last + 1;
         New_Block := Next_Block;
      end loop;

      --  Erase the data fragments which are not used by the entry.
      while Delete_Block /= null loop
         Load_Data (Manager, Delete_Block, Stream);
         Delete_Fragment (Manager    => Manager,
                          Data_Block => Delete_Block.all,
                          Next_Block => Next_Block,
                          Item       => Item);
         if Delete_Block.Count = 0 then
            Release_Data_Block (Manager, Delete_Block, Stream);
         else
            Save_Data (Manager, Delete_Block.all, Stream);
         end if;
         Delete_Block := Next_Block;
      end loop;

      Update_Entry (Manager, Item, Kind, Content'Length, Stream);
   end Update;

   procedure Add (Manager    : in out Wallet_Manager;
                  Name       : in String;
                  Kind       : in Entry_Type;
                  Content    : in Ada.Streams.Stream_Element_Array;
                  Stream     : in out IO.Wallet_Stream'Class) is
      Item        : Wallet_Entry_Access;
      Start       : Stream_Element_Offset := Content'First;
      Last        : Stream_Element_Offset;
      Block       : Wallet_Block_Entry_Access;
      Next_Block  : Wallet_Block_Entry_Access;
      Data_Offset : Ada.Streams.Stream_Element_Offset := 0;
   begin
      Add_Entry (Manager, Name, Kind, Content'Length, Item, Stream);

      if Content'Length = 0 then
         return;
      end if;

      if Item.Data.Count > 0 then
         Load_Data (Manager, Item.Data, Stream);
      else
         Init_Data_Block (Manager);
      end if;
      Block := Item.Data;

      --  Write the data in one or several blocks.
      while Block /= null loop
         if Content'Last - Start + 1 > DATA_MAX_SIZE then
            Last := Start + DATA_MAX_SIZE - 1;
            Allocate_Data_Block (Manager, DATA_MAX_SIZE, Next_Block, Stream);
         else
            Last := Content'Last;
            Next_Block := null;
         end if;
         Add_Fragment (Manager, Block, Item, Data_Offset, Next_Block, Content (Start .. Last));
         Save_Data (Manager, Block.all, Stream);
         Data_Offset := Data_Offset + Last - Start + 1;
         Start := Last + 1;
         Block := Next_Block;
      end loop;
   end Add;

   procedure Delete (Manager    : in out Wallet_Manager;
                     Name       : in String;
                     Stream     : in out IO.Wallet_Stream'Class) is
      Pos        : Wallet_Maps.Cursor := Manager.Map.Find (Name);
      Item       : Wallet_Entry_Access;
      Block      : Wallet_Block_Entry_Access;
      Next_Block : Wallet_Block_Entry_Access;
   begin
      if not Wallet_Maps.Has_Element (Pos) then
         raise Not_Found;
      end if;

      Item := Wallet_Maps.Element (Pos);
      begin
         --  Erase the data fragments used by the entry.
         Block := Item.Data;
         while Block /= null loop
            Load_Data (Manager, Block, Stream);
            Delete_Fragment (Manager    => Manager,
                             Data_Block => Block.all,
                             Next_Block => Next_Block,
                             Item       => Item);
            if Block.Count = 0 then
               Release_Data_Block (Manager, Block, Stream);
            else
               Save_Data (Manager, Block.all, Stream);
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
         Load_Data (Manager, Data_Block, Stream);
         Position := Get_Fragment_Position (Data_Block.all, Item);
         exit when Position = 0;
         Get_Fragment (Manager, Item, Position, Data_Block.Fragments (Position),
                       Output (Data_Offset .. Output'Last));
         Data_Offset := Data_Offset + Data_Block.Fragments (Position).Size;
         Data_Block := Data_Block.Fragments (Position).Next_Fragment;
      end loop;

      Result.Size := Natural (Item.Size);
      Result.Kind := Item.Kind;
      Result.Create_Date := Item.Create_Date;
      Result.Update_Date := Item.Update_Date;
   end Get_Data;

   procedure Release (Manager    : in out Wallet_Manager) is
      Block : Wallet_Block_Entry_Access;
      First : Wallet_Maps.Cursor;
      Item  : Wallet_Entry_Access;
   begin
      while not Manager.Entry_List.Is_Empty loop
         Block := Manager.Entry_List.First_Element;
         Manager.Entry_List.Delete_First;
         Free (Block);
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
         Entry_Block : Wallet_Block_Entry_Access;
      begin
         Stream.Allocate (Manager.Root);
         Manager.Id := Ident;
         Manager.Next_Id := 1;
         Keys.Create (Password, 1, Ident, Block, Manager.Root, Manager.Protect_Key,
                      Manager.IV, Manager.Cipher, Manager.Decipher, Stream);

         --  We need a new wallet directory block.
         Entry_Block := new Wallet_Block_Entry;
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
         Repo      : Safe_Wallet_Repository_Access := Wallet.Value;
         Item      : Wallet_Entry_Access;
         Wallet_Id : Wallet_Identifier := 1;
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
      begin
         Add (Manager, Name, Kind, Content, Stream);
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

      procedure Update (Name       : in String;
                        Kind       : in Entry_Type;
                        Content    : in Ada.Streams.Stream_Element_Array;
                        Stream     : in out IO.Wallet_Stream'Class) is
      begin
         Update (Manager, Name, Kind, Content, Stream);
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
            raise Not_Found;
         end if;

         Item := Wallet_Maps.Element (Pos);
         if Item.Kind = T_INVALID then
            Load_Data (Manager, Item.Data, Stream);
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
         Get_Data (Manager, Name, Result, Output, Stream);
      end Get_Data;

      procedure List (Content    : out Entry_Map;
                      Stream     : in out IO.Wallet_Stream'Class) is
         Value : Entry_Info;
      begin
         for Item of Manager.Map loop
            if Item.Kind = T_INVALID then
               Load_Data (Manager, Item.Data, Stream);
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

end Keystore.Metadata;
