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
--  | Content key      | 32b
--  | Content IV       | 16b
--  | Data block ID    | 4b
--  +------------------+
--  | ...              |
--  +------------------+
--  | Data block count | 2b
--  +------------------+
--  | Data block ID    | 4b
--  | Data header size | 2b
--  +------------------+
--  | ...              |
--  +------------------+--
--  Block encrypted with Wallet id AES-CTR key
--  +------------------+
--  | Block HMAC-256   | 32b
--  +------------------+
--  | 03 03 03 03      | 4b
--  | Wallet id        | 4b
--  | PAD 0            | 4b
--  | PAD 0            | 4b
--  +------------------+-----
--  | Entry 1 ID       | 4b  Encrypted with wallet id
--  | Entry type       | 4b
--  | Size 1           | 8b
--  | Update date      | 8b
--  | Access date      | 8b
--  | Content HMAC-256 | 32b => 64b
--  +------------------+
--  | Entry 2 ID       | 4b
--  | Entry type       | 4b
--  | Size 2           | 8b
--  | Update date      | 8b
--  | Access date      | 8b
--  | Content HMAC-256 | 32b => 64b
--  +------------------+
--  | ...              |
--  +------------------+
--  | PAD 0            |
--  +------------------+-----
--  | Data content 2   |     Encrypted with entry key 2
--  | ...              | Nb  = Size 2 (rounded to 16-byte block)
--  +------------------+-----
--  | Data content 1   |     Encrypted with entry key 1
--  | ...              | Nb  = Size 1 (rounded to 16-byte block)
--  +------------------+-----
--
package body Keystore.Metadata is

   use Ada.Streams;
   use type Interfaces.Unsigned_32;
   use type Interfaces.Unsigned_64;

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Keystore.Metadata");

   procedure Free is
     new Ada.Unchecked_Deallocation (Object => Wallet_Entry,
                                     Name   => Wallet_Entry_Access);

   procedure Free is
     new Ada.Unchecked_Deallocation (Object => Wallet_Block_Entry,
                                     Name   => Wallet_Block_Entry_Access);

   --  Start offset of the data entry descriptor in the data block.
   function Data_Entry_Offset (Index : in Natural) return IO.Block_Index;

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
      use type IO.Block_Number;
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
   begin
      --  Scan for a block having enough space for us.
      for Block of Manager.Data_List loop
         if Block.Available >= Space then
            Data_Block := Block;
            return;
         end if;
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
      Btype : Interfaces.Unsigned_32;
      Wid   : Interfaces.Unsigned_32;
   begin
      Keystore.Logs.Debug (Log, "Load directory block{0}", Dir_Block.Block);

      --  Read wallet meta data block.
      Set_IV (Manager, Dir_Block.Block);
      Stream.Read (Block    => Dir_Block.Block,
                   Decipher => Manager.Decipher,
                   Sign     => Manager.Sign,
                   Into     => Manager.Buffer);

      --  Check block type.
      Btype := IO.Get_Unsigned_32 (Manager.Buffer);
      if Btype /= IO.BT_WALLET_REPOSITORY then
         Logs.Error (Log, "Block{0} invalid block type", Dir_Block.Block);
         raise Keystore.Corrupted;
      end if;

      --  Check that this is a block for the current wallet.
      Wid := IO.Get_Unsigned_32 (Manager.Buffer);
      if Wid /= Interfaces.Unsigned_32 (Manager.Id) then
         Logs.Error (Log, "Block{0} invalid block wallet identifier", Dir_Block.Block);
         raise Keystore.Corrupted;
      end if;

      --  This is the first time we load this data block, scan the directory.
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
                  IO.Get_Secret (Manager.Buffer, Item.Key, Manager.Protect_Key);
                  IO.Get_Data (Manager.Buffer, Item.IV);
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
      Size  : constant IO.Block_Index := IO.Block_Index (Data_Block.Count * 64);
      Btype : Interfaces.Unsigned_32;
      Wid   : Interfaces.Unsigned_32;
   begin
      Logs.Debug (Log, "Load data block{0}", Data_Block.Block);

      --  Read wallet data block.
      Set_IV (Manager, Data_Block.Block);
      Stream.Read (Block        => Data_Block.Block,
                   Decrypt_Size => Size,
                   Decipher     => Manager.Decipher,
                   Sign         => Manager.Sign,
                   Into         => Manager.Buffer);

      --  Check block type.
      Btype := IO.Get_Unsigned_32 (Manager.Buffer);
      if Btype /= IO.BT_WALLET_DATA then
         Logs.Error (Log, "Block{0} invalid block type", Data_Block.Block);
         raise Keystore.Corrupted;
      end if;

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
            Prev      : Wallet_Entry_Access := null;
            Item      : Wallet_Entry_Access;
            Index     : Interfaces.Unsigned_32;
            Data_Size : IO.Block_Index;
         begin
            IO.Skip (Manager.Buffer, 8);

            while Manager.Buffer.Pos < IO.BT_DATA_START + Size loop
               Index := IO.Get_Unsigned_32 (Manager.Buffer);
               exit when Index = 0;
               Pos := Manager.Entry_Indexes.Find (Wallet_Entry_Index (Index));
               if Wallet_Indexs.Has_Element (Pos) then
                  Item := Wallet_Indexs.Element (Pos);
                  if Prev = null then
                     Data_Block.First := Item;
                  else
                     Prev.Next_Data := Item;
                  end if;
                  Prev := Item;
                  Item.Data := Data_Block;
                  Item.Next_Data := null;
                  Item := Wallet_Indexs.Element (Pos);
                  Item.Kind := IO.Get_Kind (Manager.Buffer);
                  Item.Size := IO.Get_Unsigned_64 (Manager.Buffer);
                  Item.Update_Date := IO.Get_Date (Manager.Buffer);
                  Item.Access_Date := IO.Get_Date (Manager.Buffer);
                  IO.Get_Data (Manager.Buffer, Item.Hash);

                  Data_Size := AES_Align (IO.Block_Index (Item.Size));
                  Offset := Offset - Data_Size;
                  Item.Data_Offset := Offset;
                  Data_Block.Available := Data_Block.Available - Data_Size;
                  Data_Block.Last_Pos := Offset;

               else
                  Logs.Error (Log, "Block{0} unkown index", Data_Block.Block);
                  raise Keystore.Corrupted;
               end if;
            end loop;
            Data_Block.Ready := True;
         end;
      end if;

   end Load_Data;

   --  ------------------------------
   --  Start offset of the data entry descriptor in the data block.
   --  ------------------------------
   function Data_Entry_Offset (Index : in Natural) return IO.Block_Index is
   begin
      return IO.BT_DATA_START + Stream_Element_Offset (Index * 64);
   end Data_Entry_Offset;

   --  ------------------------------
   --  Size of the wallet entry in the repository.
   --  ------------------------------
   function Entry_Size (Item : in Wallet_Entry_Access) return IO.Block_Index is
   begin
      return IO.SIZE_U32 + IO.SIZE_U16 + Item.Name'Length
        + IO.SIZE_DATE + 32 + 16 + IO.SIZE_BLOCK;
   end Entry_Size;

   --  ------------------------------
   --  Save the data block.
   --  ------------------------------
   procedure Save_Data (Manager    : in out Wallet_Manager;
                        Data_Block : in out Wallet_Block_Entry;
                        Stream     : in out IO.Wallet_Stream'Class) is
      Encrypt_Size  : IO.Block_Index;
   begin
      Keystore.Logs.Debug (Log, "Save data block{0}", Data_Block.Block);

      Set_IV (Manager, Data_Block.Block);
      Encrypt_Size := IO.Block_Index (Data_Block.Count * 64);
      Stream.Write (Block        => Data_Block.Block,
                    From         => Manager.Buffer,
                    Encrypt_Size => Encrypt_Size,
                    Cipher       => Manager.Cipher,
                    Sign         => Manager.Sign);
   end Save_Data;

   --  ------------------------------
   --  Add in the data block the wallet data entry with its content.
   --  The data block must have been loaded and is not saved.
   --  ------------------------------
   procedure Add_Data (Manager    : in out Wallet_Manager;
                       Data_Block : in out Wallet_Block_Entry;
                       Item       : in Wallet_Entry_Access;
                       Content    : in Ada.Streams.Stream_Element_Array) is
      Data_Size     : constant IO.Block_Index := AES_Align (Content'Length);
      Last_Entry    : Wallet_Entry_Access;
      Cipher_Data   : Util.Encoders.AES.Encoder;
      Start_Data    : IO.Block_Index;
      End_Data      : IO.Block_Index;
      Last_Encoded  : Ada.Streams.Stream_Element_Offset;
      Last_Pos      : Ada.Streams.Stream_Element_Offset;
   begin
      if Item.Data.First = null then
         Item.Data.First := Item;
         Item.Next_Data := null;
      else
         Last_Entry := Item.Data.First;
         while Last_Entry.Next_Data /= null loop
            Last_Entry := Last_Entry.Next_Data;
         end loop;
         Last_Entry.Next_Data := Item;
         Item.Next_Data := null;
      end if;
      Item.Size := Content'Length;

      --  Serialize the data entry at end of data entry area.
      Manager.Buffer.Pos := Data_Entry_Offset (Data_Block.Count);
      IO.Put_Unsigned_32 (Manager.Buffer, Interfaces.Unsigned_32 (Item.Id));
      IO.Put_Kind (Manager.Buffer, Item.Kind);
      IO.Put_Unsigned_64 (Manager.Buffer, Item.Size);
      IO.Put_Date (Manager.Buffer, Item.Update_Date);
      IO.Put_Date (Manager.Buffer, Item.Access_Date);

      --  Make HMAC-SHA256 signature of the data content before encryption.
      IO.Put_HMAC_SHA256 (Manager.Buffer, Manager.Sign, Content);

      Data_Block.Count := Data_Block.Count + 1;
      Data_Block.Available := Data_Block.Available - Data_Size - 64;
      Data_Block.Last_Pos := Data_Block.Last_Pos - Data_Size;
      Item.Data_Offset := Data_Block.Last_Pos;
      Start_Data := Item.Data_Offset;
      End_Data := Start_Data + Data_Size - 1;

      pragma Assert (Check => Manager.Buffer.Pos = Data_Entry_Offset (Data_Block.Count));
      pragma Assert (Check => Data_Block.Last_Pos > Data_Entry_Offset (Data_Block.Count));

      --  Encrypt the data content using the item encryption key and IV.
      Cipher_Data.Set_IV (Item.IV);
      Cipher_Data.Set_Key (Item.Key, Util.Encoders.AES.CBC);
      Cipher_Data.Set_Padding (Util.Encoders.AES.ZERO_PADDING);

      Cipher_Data.Transform (Data    => Content,
                             Into    => Manager.Buffer.Data (Start_Data .. End_Data),
                             Last    => Last_Pos,
                             Encoded => Last_Encoded);
      if Last_Pos < End_Data then
         Cipher_Data.Finish (Into => Manager.Buffer.Data (Last_Pos + 1 .. End_Data),
                             Last => Last_Pos);
      end if;
   end Add_Data;

   --  ------------------------------
   --  Delete the data from the data block.
   --  The data block must have been loaded and is not saved.
   --  ------------------------------
   procedure Delete_Data (Manager    : in out Wallet_Manager;
                          Data_Block : in out Wallet_Block_Entry;
                          Item       : in Wallet_Entry_Access) is
      Last_Pos      : IO.Block_Index;
      Start_Entry   : IO.Block_Index;
      Last_Entry    : IO.Block_Index;
      Data_Size     : IO.Block_Index;
      Wallet_Entry  : Wallet_Entry_Access;
      Prev_Entry    : Wallet_Entry_Access;
      Entry_Pos     : Natural := 0;
   begin
      Keystore.Logs.Debug (Log, "Delete data from block{0}", Data_Block.Block);

      Last_Pos := Data_Block.Last_Pos;
      Data_Size := AES_Align (IO.Block_Index (Item.Size));

      --  Unlink the item from the data block list and identify the data entry position.
      Wallet_Entry := Data_Block.First;
      while Wallet_Entry /= null and Wallet_Entry /= Item loop
         Prev_Entry := Wallet_Entry;
         Wallet_Entry := Wallet_Entry.Next_Data;
         Entry_Pos := Entry_Pos + 1;
      end loop;

      if Wallet_Entry = null then
         return;
      end if;
      if Prev_Entry /= null then
         Prev_Entry.Next_Data := Item.Next_Data;
      else
         Data_Block.First := Item.Next_Data;
      end if;

      --  Shift the data offset to take into account the move of data content.
      Wallet_Entry := Wallet_Entry.Next_Data;
      while Wallet_Entry /= null loop
         Wallet_Entry.Data_Offset := Wallet_Entry.Data_Offset + Data_Size;
         Wallet_Entry := Wallet_Entry.Next_Data;
      end loop;

      --  Move the data entry.
      Last_Entry := Data_Entry_Offset (Data_Block.Count) - 1;
      if Entry_Pos /= Data_Block.Count - 1 then
         Start_Entry := Data_Entry_Offset (Entry_Pos);
         Manager.Buffer.Data (Start_Entry .. Last_Entry - 64)
           := Manager.Buffer.Data (Start_Entry + 64 .. Last_Entry);
      end if;
      Manager.Buffer.Data (Last_Entry - 64 .. Last_Entry) := (others => 0);

      --  Move the data before the slot being removed.
      if Item.Data_Offset /= Last_Pos then
         Manager.Buffer.Data (Last_Pos + Data_Size .. Item.Data_Offset + Data_Size - 1)
           := Manager.Buffer.Data (Last_Pos .. Item.Data_Offset - 1);
      end if;

      --  Erase the content that was dropped.
      Manager.Buffer.Data (Last_Pos .. Last_Pos + Data_Size - 1) := (others => 0);
      Data_Block.Last_Pos := Data_Block.Last_Pos + Data_Size;
      Data_Block.Count := Data_Block.Count - 1;
      Data_Block.Available := Data_Block.Available + Data_Size + 64;

   end Delete_Data;

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
      Item.Kind := Kind;
      --  Item.Wallet := Self;
      Item.Size := Size;
      Item.Create_Date := Ada.Calendar.Clock;
      Item.Update_Date := Item.Create_Date;
      Item.Access_Date := Item.Create_Date;
      Item.Id := Manager.Next_Id;
      Manager.Next_Id := Manager.Next_Id + 1;
      Manager.Random.Generate (Item.Hash);
      Manager.Random.Generate (Item.IV);
      Util.Encoders.Create (Item.Hash, Item.Key);

      --  Register it in the local repository.
      Manager.Map.Insert (Name, Item);
      Manager.Entry_Indexes.Insert (Item.Id, Item);

      --  Find and load the directory block that can hold the new entry.
      Find_Directory_Block (Manager, Space, Item.Header, Stream);

      if Size > 0 then
         Allocate_Data_Block (Manager, IO.Block_Index (Size), Item.Data, Stream);
      end if;

      --  Write the new entry.
      Item.Entry_Offset := Item.Header.Last_Pos;
      Manager.Buffer.Pos := Item.Header.Last_Pos;
      IO.Put_Unsigned_32 (Manager.Buffer, Interfaces.Unsigned_32 (Item.Id));
      IO.Put_String (Manager.Buffer, Item.Name);
      IO.Put_Date (Manager.Buffer, Item.Create_Date);
      IO.Put_Secret (Manager.Buffer, Item.Key, Manager.Protect_Key);
      IO.Put_Data (Manager.Buffer, Item.IV);
      IO.Put_Block_Number (Manager.Buffer, Item.Data.Block);

      --  Remember the last valid position for the next entry to add.
      Item.Header.Last_Pos := Manager.Buffer.Pos;

      pragma Assert (Check => Manager.Buffer.Pos = Item.Entry_Offset + Entry_Size (Item));

      Set_IV (Manager, Item.Header.Block);
      Stream.Write (Block  => Item.Header.Block,
                    From   => Manager.Buffer,
                    Cipher => Manager.Cipher,
                    Sign   => Manager.Sign);
   end Add_Entry;

   --  ------------------------------
   --  Add a new entry in the wallet directory.
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

      --  Find and load the directory block that can hold the new entry.
      Load_Directory (Manager, Item.Header, Stream);

      if Size > 0 then
         Allocate_Data_Block (Manager, IO.Block_Index (Size), Item.Data, Stream);
      end if;

      --  Write the new entry.
      Manager.Buffer.Pos := Item.Entry_Offset;
      IO.Put_Unsigned_32 (Manager.Buffer, Interfaces.Unsigned_32 (Item.Id));
      IO.Put_String (Manager.Buffer, Item.Name);
      IO.Put_Date (Manager.Buffer, Item.Create_Date);
      IO.Put_Secret (Manager.Buffer, Item.Key, Manager.Protect_Key);
      IO.Put_Data (Manager.Buffer, Item.IV);
      IO.Put_Block_Number (Manager.Buffer, Item.Data.Block);

      pragma Assert (Check => Manager.Buffer.Pos = Item.Entry_Offset + Entry_Size (Item));

      Set_IV (Manager, Item.Header.Block);
      Stream.Write (Block  => Item.Header.Block,
                    From   => Manager.Buffer,
                    Cipher => Manager.Cipher,
                    Sign   => Manager.Sign);
   end Update_Entry;

   procedure Update (Manager    : in out Wallet_Manager;
                     Name       : in String;
                     Kind       : in Entry_Type;
                     Content    : in Ada.Streams.Stream_Element_Array;
                     Stream     : in out IO.Wallet_Stream'Class) is
      Size   : constant Stream_Element_Offset := AES_Align (Content'Length);
      Pos    : constant Wallet_Maps.Cursor := Manager.Map.Find (Name);
      Item   : Wallet_Entry_Access;
      Loaded : Boolean := False;
   begin
      Log.Debug ("Update keystore entry {0}", Name);

      if not Wallet_Maps.Has_Element (Pos) then
         Log.Info ("Data entry '{0}' not found", Name);
         raise Not_Found;
      end if;

      Item := Wallet_Maps.Element (Pos);

      --  Load the data block if we have partial information.
      if not Item.Data.Ready then
         Load_Data (Manager, Item.Data, Stream);
         Loaded := True;
      end if;

      --  If there is enough room in the current data block, use it.
      Item.Kind := Kind;
      if Item.Data.Available + AES_Align (Stream_Element_Offset (Item.Size)) > Size then
         if not Loaded then
            Load_Data (Manager, Item.Data, Stream);
         end if;
         Delete_Data (Manager, Item.Data.all, Item);
         Add_Data (Manager, Item.Data.all, Item, Content);
         Save_Data (Manager, Item.Data.all, Stream);
      else
         if not Loaded then
            Load_Data (Manager, Item.Data, Stream);
         end if;
         Delete_Data (Manager, Item.Data.all, Item);
         Save_Data (Manager, Item.Data.all, Stream);

         Update_Entry (Manager, Item, Kind, Content'Length, Stream);
      end if;
   end Update;

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

   --  ------------------------------
   --  Get the data associated with the named entry.
   --  ------------------------------
   procedure Get_Data (Manager    : in out Wallet_Manager;
                       Name       : in String;
                       Result     : out Entry_Info;
                       Output     : out Ada.Streams.Stream_Element_Array;
                       Stream     : in out IO.Wallet_Stream'Class) is
      Pos        : constant Wallet_Maps.Cursor := Manager.Map.Find (Name);
      Item       : Wallet_Entry_Access;
      Decipher   : Util.Encoders.AES.Decoder;
      Start_Data : IO.Block_Index;
      End_Data   : IO.Block_Index;
      Start_Pos  : Stream_Element_Offset;
      Last_Pos   : Stream_Element_Offset;
      Last       : Stream_Element_Offset;
      Encoded    : Stream_Element_Offset;
   begin
      if not Wallet_Maps.Has_Element (Pos) then
         Log.Info ("Data entry '{0}' not found", Name);
         raise Not_Found;
      end if;

      Item := Wallet_Maps.Element (Pos);
      Load_Data (Manager, Item.Data, Stream);
      if Item.Size > 0 then

         Decipher.Set_IV (Item.IV);
         Decipher.Set_Key (Item.Key, Util.Encoders.AES.CBC);
         Decipher.Set_Padding (Util.Encoders.AES.NO_PADDING);

         Start_Pos := Output'First;
         Last_Pos  := Output'Last;
         Start_Data := Item.Data_Offset;
         End_Data := Start_Data + AES_Align (IO.Block_Index (Item.Size)) - 1;
         Decipher.Transform (Data    => Manager.Buffer.Data (Start_Data .. End_Data),
                             Into    => Output (Start_Pos .. Last_Pos),
                             Last    => Last,
                             Encoded => Encoded);
         Decipher.Finish (Into => Output (Last + 1 .. Last_Pos),
                          Last => Last);
      end if;
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
         Item  : Wallet_Entry_Access;
      begin
         Add_Entry (Manager, Name, Kind, Content'Length, Item, Stream);

         if Content'Length > 0 then
            if Item.Data.Count > 0 then
               Load_Data (Manager, Item.Data, Stream);
            else
               Init_Data_Block (Manager);
            end if;
            Add_Data (Manager, Item.Data.all, Item, Content);
            Save_Data (Manager, Item.Data.all, Stream);
         end if;
      end Add;

      procedure Update (Name       : in String;
                        Kind       : in Entry_Type;
                        Content    : in Ada.Streams.Stream_Element_Array;
                        Stream     : in out IO.Wallet_Stream'Class) is
      begin
         Update (Manager, Name, Kind, Content, Stream);
      end Update;

      procedure Delete (Name       : in String;
                        Stream     : in out IO.Wallet_Stream'Class) is
         Pos  : Wallet_Maps.Cursor := Manager.Map.Find (Name);
         Item : Wallet_Entry_Access;
      begin
         if not Wallet_Maps.Has_Element (Pos) then
            raise Not_Found;
         end if;

         Item := Wallet_Maps.Element (Pos);
         begin
            Load_Data (Manager, Item.Data, Stream);
            Delete_Data (Manager    => Manager,
                         Data_Block => Item.Data.all,
                         Item       => Item);
            Save_Data (Manager, Item.Data.all, Stream);
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
