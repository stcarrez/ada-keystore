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
with Keystore.Logs;
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

      Entries.Update_Entry (Manager, Item, Kind, Content'Length, Stream);
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

      Entries.Update_Entry (Manager, Item, Kind, Interfaces.Unsigned_64 (Data_Offset), Stream);
   end Update;

   procedure Add (Manager    : in out Wallet_Manager;
                  Name       : in String;
                  Kind       : in Entry_Type;
                  Content    : in Ada.Streams.Stream_Element_Array;
                  Stream     : in out IO.Wallet_Stream'Class) is
      Item        : Wallet_Entry_Access;
      Data_Offset : Stream_Element_Offset := 0;
   begin
      Entries.Add_Entry (Manager, Name, Kind, Content'Length, Item, Stream);

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
         Entries.Delete_Entry (Manager => Manager,
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

         Entries.Load_Complete_Directory (Manager, Manager.Root, Stream);
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
         Entries.Add_Entry (Manager, Name, T_WALLET, 0, Item, Stream);

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
         Entries.Add_Entry (Manager, Name, Kind, Content'Length, Item, Stream);

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
               Entries.Add_Entry (Manager, Name, Kind,
                                  Interfaces.Unsigned_64 (Last - Content'First + 1),
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
         Data.Write (Manager, Name, Output, Stream);
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
