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
with Ada.Unchecked_Deallocation;
with Keystore.Repository.Data;
with Keystore.Repository.Entries;

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
package body Keystore.Repository is

   use type Interfaces.Unsigned_64;

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

   procedure Free is
     new Ada.Unchecked_Deallocation (Object => Keystore.Repository.Data.Wallet_Worker,
                                     Name   => Wallet_Worker_Access);

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
      null;
   end Set_Key;

   function Get_Identifier (Repository : in Wallet_Repository) return Wallet_Identifier is
   begin
      return Repository.Id;
   end Get_Identifier;

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
      Repository.Id := Ident;
      Repository.Workers := Data.Create (Repository'Unchecked_Access, null, 1).all'Access;
      Keystore.Keys.Open (Keys, Password, Ident, Block,
                          Repository.Root, Repository.Config, Stream);

      Entries.Load_Complete_Directory (Repository, Repository.Root, Stream);
   end Open;

   procedure Open (Repository : in out Wallet_Repository;
                   Name       : in String;
                   Password   : in Secret_Key;
                   Wallet     : in out Wallet_Repository;
                   Stream     : in out IO.Wallet_Stream'Class) is
   begin
      null;
   end Open;

   procedure Create (Repository : in out Wallet_Repository;
                     Password   : in Secret_Key;
                     Config     : in Wallet_Config;
                     Block      : in IO.Block_Number;
                     Ident      : in Wallet_Identifier;
                     Keys       : in out Keystore.Keys.Key_Manager;
                     Stream     : in out IO.Wallet_Stream'Class) is
      Entry_Block : Wallet_Directory_Entry_Access;
   begin
      Stream.Allocate (Repository.Root);
      Repository.Id := Ident;
      Repository.Next_Id := 1;
      Repository.Randomize := Config.Randomize;
      Repository.Config.Max_Counter := Interfaces.Unsigned_32 (Config.Max_Counter);
      Repository.Config.Min_Counter := Interfaces.Unsigned_32 (Config.Min_Counter);
      Repository.Workers := Data.Create (Repository'Unchecked_Access, null, 1).all'Access;
      Keystore.Keys.Create (Keys, Password, 1, Ident, Block, Repository.Root,
                            Repository.Config, Stream);

      --  We need a new wallet directory block.
      Entry_Block := new Wallet_Directory_Entry;
      Entry_Block.Available := IO.Block_Index'Last - IO.BT_DATA_START - 4;
      Entry_Block.Count := 0;
      Entry_Block.Last_Pos := IO.BT_DATA_START + 4;
      Entry_Block.Ready := True;
      Entry_Block.Block := Repository.Root;
      Repository.Entry_List.Append (Entry_Block);

      Repository.Buffer.Data := (others => 0);
      IO.Set_Header (Into => Repository.Buffer,
                     Tag  => IO.BT_WALLET_REPOSITORY,
                     Id   => Interfaces.Unsigned_32 (Repository.Id));
      Keystore.Keys.Set_IV (Repository.Config.Dir, Repository.Root);
      Stream.Write (Block  => Repository.Root,
                    From   => Repository.Buffer,
                    Cipher => Repository.Config.Dir.Cipher,
                    Sign   => Repository.Config.Dir.Sign);
   end Create;

   procedure Add (Repository : in out Wallet_Repository;
                  Name       : in String;
                  Kind       : in Entry_Type;
                  Content    : in Ada.Streams.Stream_Element_Array;
                  Stream     : in out IO.Wallet_Stream'Class) is
      Item        : Wallet_Entry_Access;
      Data_Offset : Stream_Element_Offset := 0;
   begin
      Entries.Add_Entry (Repository, Name, Kind, Content'Length, Item, Stream);

      if Content'Length = 0 then
         return;
      end if;

      Data.Add_Data (Repository, Item, Item.Data, Content, Data_Offset, Stream);
   end Add;

   procedure Add (Repository : in out Wallet_Repository;
                  Name       : in String;
                  Kind       : in Entry_Type;
                  Input      : in out Util.Streams.Input_Stream'Class;
                  Stream     : in out IO.Wallet_Stream'Class) is
      Item        : Wallet_Entry_Access;
      Data_Offset : Stream_Element_Offset := 0;
   begin
      Entries.Add_Entry (Repository, Name, Kind, 1, Item, Stream);

      Data.Add_Data (Repository, Item, Item.Data, Input, Data_Offset, Stream);
   end Add;

   procedure Add_Wallet (Repository : in out Wallet_Repository;
                         Name       : in String;
                         Password   : in Secret_Key;
                         Wallet     : out Wallet_Repository'Class;
                         Stream     : in out IO.Wallet_Stream'Class) is
      Item      : Wallet_Entry_Access;
      --  Keys      : Keystore.Keys.Key_Manager;
   begin
      Entries.Add_Entry (Repository, Name, T_WALLET, 0, Item, Stream);

      Stream.Allocate (Item.Block);

      --  Keys.Set_Header_Key
      --  Repo.Create (Password, 1, IO.Block_Number (Item.Block), Keys, Stream);

      --  Repository.Value.Add (Name, Password, Wallet, Stream);
   end Add_Wallet;

   procedure Set (Repository : in out Wallet_Repository;
                  Name       : in String;
                  Kind       : in Entry_Type;
                  Content    : in Ada.Streams.Stream_Element_Array;
                  Stream     : in out IO.Wallet_Stream'Class) is
   begin
      if Repository.Map.Contains (Name) then
         Repository.Update (Name, Kind, Content, Stream);
      else
         Repository.Add (Name, Kind, Content, Stream);
      end if;
   end Set;

   procedure Set (Repository : in out Wallet_Repository;
                  Name       : in String;
                  Kind       : in Entry_Type;
                  Input      : in out Util.Streams.Input_Stream'Class;
                  Stream     : in out IO.Wallet_Stream'Class) is
   begin
      if Repository.Map.Contains (Name) then
         Repository.Update (Name, Kind, Input, Stream);
      else
         Repository.Add (Name, Kind, Input, Stream);
      end if;
   end Set;

   procedure Update (Repository : in out Wallet_Repository;
                     Name       : in String;
                     Kind       : in Entry_Type;
                     Content    : in Ada.Streams.Stream_Element_Array;
                     Stream     : in out IO.Wallet_Stream'Class) is
      Pos          : constant Wallet_Maps.Cursor := Repository.Map.Find (Name);
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
      Data.Update_Data (Repository, Item, Data_Block, Content,
                        Data_Offset, True, New_Block, Delete_Block, Stream);

      --  Write the data in one or several blocks.
      if New_Block /= null then
         Start := Content'First + Data_Offset;
         Data.Add_Data (Repository, Item, New_Block, Content (Start .. Content'Last),
                        Data_Offset, Stream);
      end if;

      if Delete_Block /= null then
         Data.Delete_Data (Repository, Item, Delete_Block, Stream);
      end if;

      Entries.Update_Entry (Repository, Item, Kind, Content'Length, Stream);
   end Update;

   procedure Update (Manager    : in out Wallet_Repository;
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
                              Data_Offset, Stream);
               exit;
            else
               --  Write the data in one or several blocks.
               Data.Add_Data (Manager, Item, New_Block, Content,
                              Data_Offset, Stream);
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

      Entries.Update_Entry (Manager, Item, Kind, Interfaces.Unsigned_64 (Data_Offset), Stream);
   end Update;

   --  ------------------------------
   --  Delete the value associated with the given name.
   --  Raises the Not_Found exception if the name was not found.
   --  ------------------------------
   procedure Delete (Repository : in out Wallet_Repository;
                     Name       : in String;
                     Stream     : in out IO.Wallet_Stream'Class) is
      Pos        : Wallet_Maps.Cursor := Repository.Map.Find (Name);
      Item       : Wallet_Entry_Access;
   begin
      if not Wallet_Maps.Has_Element (Pos) then
         Log.Info ("Data entry '{0}' not found", Name);
         raise Not_Found;
      end if;

      Item := Wallet_Maps.Element (Pos);
      begin
         --  Erase the data fragments used by the entry.
         Data.Delete_Data (Repository, Item, Item.Data, Stream);

         --  Erase the entry from the repository.
         Entries.Delete_Entry (Manager => Repository,
                               Item    => Item,
                               Stream  => Stream);
      exception
         when others =>
            --  Handle data or directory block corruption or IO error.
            Repository.Entry_Indexes.Delete (Item.Id);
            Repository.Map.Delete (Pos);
            Free (Item);
            raise;
      end;
      Repository.Entry_Indexes.Delete (Item.Id);
      Repository.Map.Delete (Pos);
      Free (Item);
   end Delete;

   function Contains (Repository : in Wallet_Repository;
                      Name       : in String) return Boolean is
   begin
      return Repository.Map.Contains (Name);
   end Contains;

   procedure Find (Repository : in out Wallet_Repository;
                   Name       : in String;
                   Result     : out Entry_Info;
                   Stream     : in out IO.Wallet_Stream'Class) is
      Pos  : constant Wallet_Maps.Cursor := Repository.Map.Find (Name);
      Item : Wallet_Entry_Access;
   begin
      if not Wallet_Maps.Has_Element (Pos) then
         Log.Info ("Data entry '{0}' not found", Name);
         raise Not_Found;
      end if;

      Item := Wallet_Maps.Element (Pos);
      if Item.Kind = T_INVALID then
         Data.Load_Data (Repository, Item.Data, Repository.Buffer, Stream);
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

   procedure Get_Data (Repository : in out Wallet_Repository;
                       Name       : in String;
                       Result     : out Entry_Info;
                       Output     : out Ada.Streams.Stream_Element_Array;
                       Stream     : in out IO.Wallet_Stream'Class) is
   begin
      Data.Get_Data (Repository, Name, Result, Output, Stream);
   end Get_Data;

   procedure Write (Repository : in out Wallet_Repository;
                    Name       : in String;
                    Output     : in out Util.Streams.Output_Stream'Class;
                    Stream     : in out IO.Wallet_Stream'Class) is
   begin
      Data.Write (Repository, Name, Output, Stream);
   end Write;

   --  Get the list of entries contained in the wallet.
   procedure List (Repository : in out Wallet_Repository;
                   Content    : out Entry_Map;
                   Stream     : in out IO.Wallet_Stream'Class) is
      Value : Entry_Info;
   begin
      for Item of Repository.Map loop
         if Item.Kind = T_INVALID then
            Data.Load_Data (Repository, Item.Data, Repository.Buffer, Stream);
         end if;
         Value.Size := Integer (Item.Size);
         Value.Kind := Item.Kind;
         Value.Create_Date := Item.Create_Date;
         Value.Update_Date := Item.Update_Date;
         Content.Include (Key      => Item.Name,
                          New_Item => Value);
      end loop;
   end List;

   procedure Close (Repository : in out Wallet_Repository) is
      Dir   : Wallet_Directory_Entry_Access;
      Block : Wallet_Block_Entry_Access;
      First : Wallet_Maps.Cursor;
      Item  : Wallet_Entry_Access;
   begin
      while not Repository.Entry_List.Is_Empty loop
         Dir := Repository.Entry_List.First_Element;
         Repository.Entry_List.Delete_First;
         Free (Dir);
      end loop;
      while not Repository.Data_List.Is_Empty loop
         Block := Repository.Data_List.First_Element;
         Repository.Data_List.Delete_First;
         Free (Block);
      end loop;

      Repository.Entry_Indexes.Clear;
      while not Repository.Map.Is_Empty loop
         First := Repository.Map.First;
         Item := Wallet_Maps.Element (First);
         Free (Item);
         Repository.Map.Delete (First);
      end loop;
      Free (Repository.Workers);
   end Close;

   procedure Set_Work_Manager (Repository : in out Wallet_Repository;
                               Workers    : in Keystore.Task_Manager_Access) is
   begin
      Free (Repository.Workers);
      Repository.Workers
        := Data.Create (Repository'Unchecked_Access, Workers, Workers.Count).all'Access;
   end Set_Work_Manager;

   overriding
   procedure Finalize (Manager    : in out Wallet_Repository) is
   begin
      Manager.Close;
   end Finalize;

end Keystore.Repository;
