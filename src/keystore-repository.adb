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
with Keystore.Marshallers;
with Keystore.Repository.Data;
with Keystore.Repository.Entries;
with Keystore.Repository.Workers;
with Keystore.Repository.Keys;

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
     new Ada.Unchecked_Deallocation (Object => Wallet_Directory_Entry,
                                     Name   => Wallet_Directory_Entry_Access);

   procedure Free is
     new Ada.Unchecked_Deallocation (Object => Keystore.Repository.Workers.Wallet_Worker,
                                     Name   => Wallet_Worker_Access);

   function Hash (Value : in Wallet_Entry_Index) return Ada.Containers.Hash_Type is
   begin
      return Ada.Containers.Hash_Type (Value);
   end Hash;

   function Get_Identifier (Repository : in Wallet_Repository) return Wallet_Identifier is
   begin
      return Repository.Id;
   end Get_Identifier;

   --  Open the wallet repository by reading the meta data block header from the wallet
   --  IO stream.  The wallet meta data is decrypted using AES-CTR using the given secret
   --  key and initial vector.
   procedure Open (Repository : in out Wallet_Repository;
                   Password   : in out Keystore.Passwords.Provider'Class;
                   Ident      : in Wallet_Identifier;
                   Block      : in Keystore.IO.Storage_Block;
                   Keys       : in out Keystore.Keys.Key_Manager;
                   Stream     : in IO.Wallet_Stream_Access) is
   begin
      Repository.Id := Ident;
      Repository.Stream := Stream;
      Repository.Next_Id := 1;
      Repository.Next_Wallet_Id := Ident + 1;
      Keystore.Keys.Open (Keys, Password, Ident, Block,
                          Repository.Root, Repository.Config, null, Stream.all);
      Repository.Workers := Workers.Create (Repository'Unchecked_Access, null, 1).all'Access;

      Entries.Load_Complete_Directory (Repository, Repository.Root);
   end Open;

   procedure Open (Repository : in out Wallet_Repository;
                   Name       : in String;
                   Password   : in out Keystore.Passwords.Provider'Class;
                   Keys       : in out Keystore.Keys.Key_Manager;
                   Master_Block : in out Keystore.IO.Storage_Block;
                   Master_Ident : in out Wallet_Identifier;
                   Wallet     : in out Wallet_Repository) is
      Pos : constant Wallet_Maps.Cursor := Repository.Map.Find (Name);
   begin
      if not Wallet_Maps.Has_Element (Pos) then
         Log.Info ("Wallet entry '{0}' not found", Name);
         raise Not_Found;
      end if;
      declare
         Item     : constant Wallet_Entry_Access := Wallet_Maps.Element (Pos);
      begin
         if Item.Kind /= T_WALLET then
            raise Invalid_Keystore;
         end if;
         Master_Block := Repository.Root;
         Master_Block.Block := Item.Master;
         Master_Ident := Item.Wallet_Id;
         Wallet.Stream := Repository.Stream;
         Wallet.Next_Id := 1;
         Wallet.Id := Item.Wallet_Id;
         Wallet.Parent := Repository'Unchecked_Access;
         Keystore.Repository.Keys.Open_Wallet (Repository, Item, Keys);
         Keystore.Keys.Open (Keys, Password, Wallet.Id, Master_Block,
                             Wallet.Root, Wallet.Config, null, Repository.Stream.all);
         Wallet.Workers := Workers.Create (Wallet'Unchecked_Access, null, 1).all'Access;

         Entries.Load_Complete_Directory (Wallet, Wallet.Root);
      end;
   end Open;

   procedure Create (Repository : in out Wallet_Repository;
                     Password   : in out Keystore.Passwords.Provider'Class;
                     Config     : in Wallet_Config;
                     Block      : in IO.Storage_Block;
                     Ident      : in Wallet_Identifier;
                     Keys       : in out Keystore.Keys.Key_Manager;
                     Stream     : in IO.Wallet_Stream_Access) is
      Entry_Block : Wallet_Directory_Entry_Access;
   begin
      Stream.Allocate (IO.DIRECTORY_BLOCK, Repository.Root);
      Repository.Id := Ident;
      Repository.Next_Id := 1;
      Repository.Next_Wallet_Id := Ident + 1;
      Repository.Stream := Stream;
      Repository.Randomize := Config.Randomize;
      Repository.Config.Randomize := Config.Randomize;
      Repository.Config.Max_Counter := Interfaces.Unsigned_32 (Config.Max_Counter);
      Repository.Config.Min_Counter := Interfaces.Unsigned_32 (Config.Min_Counter);
      Keystore.Keys.Create (Keys, Password, 1, Ident, Block, Repository.Root,
                            Repository.Config, Stream.all);
      Repository.Workers := Workers.Create (Repository'Unchecked_Access, null, 1).all'Access;

      --  We need a new wallet directory block.
      Entries.Initialize_Directory_Block (Repository, Repository.Root, 0, Entry_Block);

      Repository.Current.Buffer := Buffers.Allocate (Repository.Root);
      Repository.Current.Buffer.Data.Value.Data := (others => 0);
      Marshallers.Set_Header (Into => Repository.Current,
                              Tag  => IO.BT_WALLET_DIRECTORY,
                              Id   => Repository.Id);
      Marshallers.Put_Unsigned_32 (Repository.Current, 0);
      Marshallers.Put_Block_Index (Repository.Current, IO.Block_Index'Last);
      Keystore.Keys.Set_IV (Repository.Config.Dir, Repository.Root.Block);
      Stream.Write (From   => Repository.Current.Buffer,
                    Cipher => Repository.Config.Dir.Cipher,
                    Sign   => Repository.Config.Dir.Sign);
   end Create;

   procedure Add (Repository : in out Wallet_Repository;
                  Name       : in String;
                  Kind       : in Entry_Type;
                  Content    : in Ada.Streams.Stream_Element_Array) is
      Item        : Wallet_Entry_Access;
      Data_Offset : Interfaces.Unsigned_64 := 0;
      Iterator    : Keys.Data_Key_Iterator;
   begin
      Entries.Add_Entry (Repository, Name, Kind, Item);
      Entries.Update_Entry (Repository, Item, Kind, Content'Length);

      if Content'Length > 0 then
         Keys.Initialize (Repository, Iterator, Item);

         Data.Add_Data (Repository, Iterator, Content, Data_Offset);

         Entries.Update_Entry (Repository, Item, Kind, Data_Offset);
      end if;

      Entries.Save (Manager => Repository);
   end Add;

   procedure Add (Repository : in out Wallet_Repository;
                  Name       : in String;
                  Kind       : in Entry_Type;
                  Input      : in out Util.Streams.Input_Stream'Class) is
      Item        : Wallet_Entry_Access;
      Data_Offset : Interfaces.Unsigned_64 := 0;
      Iterator    : Keys.Data_Key_Iterator;
   begin
      Entries.Add_Entry (Repository, Name, Kind, Item);
      Entries.Update_Entry (Repository, Item, Kind, 1);

      Keys.Initialize (Repository, Iterator, Item);

      Data.Add_Data (Repository, Iterator, Input, Data_Offset);

      Entries.Update_Entry (Repository, Item, Kind, Data_Offset);

      Entries.Save (Manager => Repository);
   end Add;

   procedure Add_Wallet (Repository : in out Wallet_Repository;
                         Name       : in String;
                         Password   : in out Keystore.Passwords.Provider'Class;
                         Keys       : in out Keystore.Keys.Key_Manager;
                         Master_Block : in out Keystore.IO.Storage_Block;
                         Master_Ident : in out Wallet_Identifier;
                         Wallet     : in out Wallet_Repository) is
      Item   : Wallet_Entry_Access;
      Entry_Block : Wallet_Directory_Entry_Access;
   begin
      Entries.Add_Entry (Repository, Name, T_WALLET, Item);

      --  Repository.Value.Add (Name, Password, Wallet, Stream);
      Repository.Stream.Allocate (IO.MASTER_BLOCK, Master_Block);
      Repository.Stream.Allocate (IO.DIRECTORY_BLOCK, Wallet.Root);
      Item.Master := Master_Block.Block;

      Wallet.Stream := Repository.Stream;
      Wallet.Next_Id := 1;
      Wallet.Id := Item.Wallet_Id;
      Master_Ident := Wallet.Id;

      Entries.Update_Entry (Repository, Item, T_WALLET, 0);

      Keystore.Repository.Keys.Create_Wallet (Repository, Item, Master_Block, Keys);
      Keystore.Keys.Create (Keys, Password, 1, Master_Ident, Master_Block, Wallet.Root,
                            Wallet.Config, Repository.Stream.all);

      --  We need a new wallet directory block.
      Entries.Initialize_Directory_Block (Wallet, Wallet.Root, 0, Entry_Block);
      Entries.Save (Repository);

      Wallet.Current.Buffer := Buffers.Allocate (Wallet.Root);
      Wallet.Current.Buffer.Data.Value.Data := (others => 0);
      Marshallers.Set_Header (Into => Wallet.Current,
                              Tag  => IO.BT_WALLET_DIRECTORY,
                              Id   => Wallet.Id);
      Marshallers.Put_Unsigned_32 (Wallet.Current, 0);
      Marshallers.Put_Block_Index (Wallet.Current, IO.Block_Index'Last);
      Keystore.Keys.Set_IV (Wallet.Config.Dir, Wallet.Root.Block);
      Repository.Stream.Write (From   => Wallet.Current.Buffer,
                               Cipher => Wallet.Config.Dir.Cipher,
                               Sign   => Wallet.Config.Dir.Sign);

      Wallet.Workers := Workers.Create (Wallet'Unchecked_Access, null, 1).all'Access;
   end Add_Wallet;

   procedure Set (Repository : in out Wallet_Repository;
                  Name       : in String;
                  Kind       : in Entry_Type;
                  Content    : in Ada.Streams.Stream_Element_Array) is
   begin
      if Repository.Map.Contains (Name) then
         Repository.Update (Name, Kind, Content);
      else
         Repository.Add (Name, Kind, Content);
      end if;
   end Set;

   procedure Set (Repository : in out Wallet_Repository;
                  Name       : in String;
                  Kind       : in Entry_Type;
                  Input      : in out Util.Streams.Input_Stream'Class) is
   begin
      if Repository.Map.Contains (Name) then
         Repository.Update (Name, Kind, Input);
      else
         Repository.Add (Name, Kind, Input);
      end if;
   end Set;

   procedure Update (Repository : in out Wallet_Repository;
                     Name       : in String;
                     Kind       : in Entry_Type;
                     Content    : in Ada.Streams.Stream_Element_Array) is
      Pos          : constant Wallet_Maps.Cursor := Repository.Map.Find (Name);
      Data_Offset  : Interfaces.Unsigned_64 := 0;
   begin
      Log.Debug ("Update keystore entry {0}", Name);

      if not Wallet_Maps.Has_Element (Pos) then
         Log.Info ("Data entry '{0}' not found", Name);
         raise Not_Found;
      end if;

      declare
         Item     : constant Wallet_Entry_Access := Wallet_Maps.Element (Pos);
         Iterator : Keys.Data_Key_Iterator;
         Last_Pos : Stream_Element_Offset;
      begin
         if Item.Is_Wallet then
            Log.Info ("Data entry '{0}' is a wallet", Name);
            raise No_Content;
         end if;
         Item.Kind := Kind;
         Keys.Initialize (Repository, Iterator, Item);

         Data.Update_Data (Repository, Iterator, Content, Last_Pos, Data_Offset);

         if Last_Pos > Content'Last then
            Data.Delete_Data (Repository, Iterator);
         else
            Data.Add_Data (Repository, Iterator,
                           Content (Last_Pos .. Content'Last), Data_Offset);
         end if;

         Entries.Update_Entry (Repository, Item, Kind, Data_Offset);

         Entries.Save (Repository);
      end;
   end Update;

   procedure Update (Repository : in out Wallet_Repository;
                     Name       : in String;
                     Kind       : in Entry_Type;
                     Input      : in out Util.Streams.Input_Stream'Class) is
      Item_Pos     : constant Wallet_Maps.Cursor := Repository.Map.Find (Name);
      Data_Offset  : Interfaces.Unsigned_64 := 0;
   begin
      Log.Debug ("Update keystore entry {0}", Name);

      if not Wallet_Maps.Has_Element (Item_Pos) then
         Log.Info ("Data entry '{0}' not found", Name);
         raise Not_Found;
      end if;

      declare
         Item          : constant Wallet_Entry_Access := Wallet_Maps.Element (Item_Pos);
         Iterator      : Keys.Data_Key_Iterator;
         End_Of_Stream : Boolean;
      begin
         if Item.Is_Wallet then
            Log.Info ("Data entry '{0}' is a wallet", Name);
            raise No_Content;
         end if;
         Item.Kind := Kind;
         Keys.Initialize (Repository, Iterator, Item);

         Data.Update_Data (Repository, Iterator, Input, End_Of_Stream, Data_Offset);
         if End_Of_Stream then
            Data.Delete_Data (Repository, Iterator);
         else
            Data.Add_Data (Repository, Iterator, Input, Data_Offset);
         end if;

         Entries.Update_Entry (Repository, Item, Kind, Data_Offset);

         Entries.Save (Repository);
      end;
   end Update;

   --  ------------------------------
   --  Delete the value associated with the given name.
   --  Raises the Not_Found exception if the name was not found.
   --  ------------------------------
   procedure Delete (Repository : in out Wallet_Repository;
                     Name       : in String) is
      Pos        : Wallet_Maps.Cursor := Repository.Map.Find (Name);
   begin
      if not Wallet_Maps.Has_Element (Pos) then
         Log.Info ("Data entry '{0}' not found", Name);
         raise Not_Found;
      end if;

      declare
         Item     : Wallet_Entry_Access := Wallet_Maps.Element (Pos);
         Iterator : Keys.Data_Key_Iterator;
      begin
         Keys.Initialize (Repository, Iterator, Item);

         --  Erase the data fragments used by the entry.
         Data.Delete_Data (Repository, Iterator);

         --  Erase the entry from the repository.
         Entries.Delete_Entry (Manager => Repository,
                               Item    => Item);

         Entries.Save (Manager => Repository);
         Repository.Entry_Indexes.Delete (Item.Id);
         Repository.Map.Delete (Pos);
         Free (Item);

      exception
         when others =>
            --  Handle data or directory block corruption or IO error.
            Repository.Entry_Indexes.Delete (Item.Id);
            Repository.Map.Delete (Pos);
            Free (Item);
            raise;
      end;

   end Delete;

   function Contains (Repository : in Wallet_Repository;
                      Name       : in String) return Boolean is
   begin
      return Repository.Map.Contains (Name);
   end Contains;

   procedure Find (Repository : in out Wallet_Repository;
                   Name       : in String;
                   Result     : out Entry_Info) is
      Pos  : constant Wallet_Maps.Cursor := Repository.Map.Find (Name);
      Item : Wallet_Entry_Access;
   begin
      if not Wallet_Maps.Has_Element (Pos) then
         Log.Info ("Data entry '{0}' not found", Name);
         raise Not_Found;
      end if;

      Item := Wallet_Maps.Element (Pos);
      if Item.Kind = T_INVALID then
         Log.Error ("Wallet entry {0} is corrupted", Name);
         raise Corrupted;
      end if;
      if not Item.Is_Wallet then
         Result.Size := Item.Size;
         Result.Block_Count := Item.Block_Count;
      else
         Result.Size := 0;
         Result.Block_Count := 0;
      end if;
      Result.Kind := Item.Kind;
      Result.Create_Date := Item.Create_Date;
      Result.Update_Date := Item.Update_Date;
   end Find;

   procedure Get_Data (Repository : in out Wallet_Repository;
                       Name       : in String;
                       Result     : out Entry_Info;
                       Output     : out Ada.Streams.Stream_Element_Array) is
      Pos : constant Wallet_Maps.Cursor := Repository.Map.Find (Name);
   begin
      if not Wallet_Maps.Has_Element (Pos) then
         Log.Info ("Data entry '{0}' not found", Name);
         raise Not_Found;
      end if;
      declare
         Item     : constant Wallet_Entry_Access := Wallet_Maps.Element (Pos);
         Iterator : Keys.Data_Key_Iterator;
      begin
         if Item.Is_Wallet then
            Log.Info ("Data entry '{0}' is a wallet", Name);
            raise No_Content;
         end if;
         Result.Size := Item.Size;
         Result.Kind := Item.Kind;
         Result.Create_Date := Item.Create_Date;
         Result.Update_Date := Item.Update_Date;

         Keys.Initialize (Repository, Iterator, Item);
         Data.Get_Data (Repository, Iterator, Output);
         if Iterator.Current_Offset /= Item.Size then
            pragma Assert (Iterator.Current_Offset = Item.Size);
         end if;
      end;
   end Get_Data;

   procedure Get_Data (Repository : in out Wallet_Repository;
                       Name       : in String;
                       Output     : in out Util.Streams.Output_Stream'Class) is
      Pos : constant Wallet_Maps.Cursor := Repository.Map.Find (Name);
   begin
      if not Wallet_Maps.Has_Element (Pos) then
         Log.Info ("Data entry '{0}' not found", Name);
         raise Not_Found;
      end if;
      declare
         Item     : constant Wallet_Entry_Access := Wallet_Maps.Element (Pos);
         Iterator : Keys.Data_Key_Iterator;
      begin
         if Item.Is_Wallet then
            Log.Info ("Data entry '{0}' is a wallet", Name);
            raise No_Content;
         end if;
         Keys.Initialize (Repository, Iterator, Item);
         Data.Get_Data (Repository, Iterator, Output);
      end;
   end Get_Data;

   --  ------------------------------
   --  Get the list of entries contained in the wallet that correspond to the optional filter.
   --  ------------------------------
   procedure List (Repository : in out Wallet_Repository;
                   Filter     : in Filter_Type;
                   Content    : out Entry_Map) is
      Value : Entry_Info;
   begin
      for Item of Repository.Map loop
         if Filter (Item.Kind) then
            if not Item.Is_Wallet then
               Value.Size := Item.Size;
               Value.Block_Count := Item.Block_Count;
            else
               Value.Size := 0;
               Value.Block_Count := 1;
            end if;
            Value.Kind := Item.Kind;
            Value.Create_Date := Item.Create_Date;
            Value.Update_Date := Item.Update_Date;
            Content.Include (Key      => Item.Name,
                             New_Item => Value);
         end if;
      end loop;
   end List;

   procedure List (Repository : in out Wallet_Repository;
                   Pattern    : in GNAT.Regpat.Pattern_Matcher;
                   Filter     : in Filter_Type;
                   Content    : out Entry_Map) is
      Value : Entry_Info;
   begin
      for Item of Repository.Map loop
         if Filter (Item.Kind) and then GNAT.Regpat.Match (Pattern, Item.Name) then
            if not Item.Is_Wallet then
               Value.Size := Item.Size;
               Value.Block_Count := Item.Block_Count;
            else
               Value.Size := 0;
               Value.Block_Count := 1;
            end if;
            Value.Kind := Item.Kind;
            Value.Create_Date := Item.Create_Date;
            Value.Update_Date := Item.Update_Date;
            Content.Include (Key      => Item.Name,
                             New_Item => Value);
         end if;
      end loop;
   end List;

   --  ------------------------------
   --  Get the keystore UUID.
   --  ------------------------------
   function Get_UUID (Repository : in Wallet_Repository) return UUID_Type is
   begin
      return Repository.Config.UUID;
   end Get_UUID;

   --  ------------------------------
   --  Get the key slot number that was used to unlock the keystore.
   --  ------------------------------
   function Get_Key_Slot (Repository : in Wallet_Repository) return Key_Slot is
   begin
      return Repository.Config.Slot;
   end Get_Key_Slot;

   --  ------------------------------
   --  Get stats information about the wallet (the number of entries, used key slots).
   --  ------------------------------
   procedure Fill_Stats (Repository : in Wallet_Repository;
                         Stats      : in out Wallet_Stats) is
   begin
      Stats.UUID := Repository.Config.UUID;
      Stats.Keys := Repository.Config.Keys;
      Stats.Entry_Count := Natural (Repository.Map.Length);
   end Fill_Stats;

   procedure Close (Repository : in out Wallet_Repository) is
      Dir   : Wallet_Directory_Entry_Access;
      First : Wallet_Maps.Cursor;
      Item  : Wallet_Entry_Access;
   begin
      while not Repository.Directory_List.Is_Empty loop
         Dir := Repository.Directory_List.First_Element;
         Repository.Directory_List.Delete_First;
         Free (Dir);
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
        := Keystore.Repository.Workers.Create (Repository'Unchecked_Access,
                                               Workers, Workers.Count).all'Access;
   end Set_Work_Manager;

   overriding
   procedure Finalize (Manager    : in out Wallet_Repository) is
   begin
      Manager.Close;
   end Finalize;

end Keystore.Repository;
