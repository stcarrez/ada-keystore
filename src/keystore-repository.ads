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
with Ada.Calendar;
with Util.Encoders.AES;
with Keystore.IO;
with Ada.Streams;
with Keystore.Keys;
with Util.Streams;
with Interfaces;

with Ada.Containers.Indefinite_Hashed_Maps;
with Ada.Containers.Doubly_Linked_Lists;
with Ada.Strings.Hash;

private with Keystore.Random;
private with Ada.Containers.Ordered_Maps;
private with Ada.Finalization;
limited private with Keystore.Repository.Data;
private package Keystore.Repository is

   type Wallet_Repository is tagged limited private;

   function Get_Identifier (Repository : in Wallet_Repository) return Wallet_Identifier;

   --  Open the wallet repository by reading the meta data block header from the wallet
   --  IO stream.  The wallet meta data is decrypted using AES-CTR using the given secret
   --  key and initial vector.
   procedure Open (Repository : in out Wallet_Repository;
                   Password   : in Secret_Key;
                   Ident      : in Wallet_Identifier;
                   Block      : in Keystore.IO.Block_Number;
                   Keys       : in out Keystore.Keys.Key_Manager;
                   Stream     : in out IO.Wallet_Stream'Class);

   procedure Open (Repository : in out Wallet_Repository;
                   Name       : in String;
                   Password   : in Secret_Key;
                   Wallet     : in out Wallet_Repository;
                   Stream     : in out IO.Wallet_Stream'Class);

   procedure Create (Repository : in out Wallet_Repository;
                     Password   : in Secret_Key;
                     Config     : in Wallet_Config;
                     Block      : in IO.Block_Number;
                     Ident      : in Wallet_Identifier;
                     Keys       : in out Keystore.Keys.Key_Manager;
                     Stream     : in out IO.Wallet_Stream'Class);

   procedure Add (Repository : in out Wallet_Repository;
                  Name       : in String;
                  Kind       : in Entry_Type;
                  Content    : in Ada.Streams.Stream_Element_Array;
                  Stream     : in out IO.Wallet_Stream'Class);

   procedure Add_Wallet (Repository : in out Wallet_Repository;
                         Name       : in String;
                         Password   : in Secret_Key;
                         Wallet     : out Wallet_Repository'Class;
                         Stream     : in out IO.Wallet_Stream'Class);

   procedure Set (Repository : in out Wallet_Repository;
                  Name       : in String;
                  Kind       : in Entry_Type;
                  Content    : in Ada.Streams.Stream_Element_Array;
                  Stream     : in out IO.Wallet_Stream'Class);

   procedure Set (Repository : in out Wallet_Repository;
                  Name       : in String;
                  Kind       : in Entry_Type;
                  Input      : in out Util.Streams.Input_Stream'Class;
                  Stream     : in out IO.Wallet_Stream'Class);

   procedure Update (Repository : in out Wallet_Repository;
                     Name       : in String;
                     Kind       : in Entry_Type;
                     Content    : in Ada.Streams.Stream_Element_Array;
                     Stream     : in out IO.Wallet_Stream'Class);

   procedure Update (Manager    : in out Wallet_Repository;
                     Name       : in String;
                     Kind       : in Entry_Type;
                     Input      : in out Util.Streams.Input_Stream'Class;
                     Stream     : in out IO.Wallet_Stream'Class);

   procedure Delete (Repository : in out Wallet_Repository;
                     Name       : in String;
                     Stream     : in out IO.Wallet_Stream'Class);

   function Contains (Repository : in Wallet_Repository;
                      Name       : in String) return Boolean;

   procedure Find (Repository : in out Wallet_Repository;
                   Name       : in String;
                   Result     : out Entry_Info;
                   Stream     : in out IO.Wallet_Stream'Class);

   procedure Get_Data (Repository : in out Wallet_Repository;
                       Name       : in String;
                       Result     : out Entry_Info;
                       Output     : out Ada.Streams.Stream_Element_Array;
                       Stream     : in out IO.Wallet_Stream'Class);

   --  Write in the output stream the named entry value from the wallet.
   procedure Write (Repository : in out Wallet_Repository;
                    Name       : in String;
                    Output     : in out Util.Streams.Output_Stream'Class;
                    Stream     : in out IO.Wallet_Stream'Class);

   --  Get the list of entries contained in the wallet.
   procedure List (Repository : in out Wallet_Repository;
                   Content    : out Entry_Map;
                   Stream     : in out IO.Wallet_Stream'Class);

   procedure Set_Work_Manager (Repository : in out Wallet_Repository;
                               Workers    : in Keystore.Task_Manager_Access);

   procedure Close (Repository : in out Wallet_Repository);

private

   use Ada.Streams;

   function AES_Align (Size : in Stream_Element_Offset) return Stream_Element_Offset
     renames Util.Encoders.AES.Align;

   ET_WALLET_ENTRY      : constant := 16#0001#;
   ET_STRING_ENTRY      : constant := 16#0010#;
   ET_BINARY_ENTRY      : constant := 16#0200#;

   WH_KEY_SIZE          : constant := 256;
   WALLET_ENTRY_SIZE    : constant := 4 + 2 + 8 + 32 + 16 + 4;

   DATA_IV_OFFSET       : constant := 32;
   DATA_ENTRY_SIZE      : constant := 112;
   DATA_MAX_SIZE        : constant := IO.Block_Size - IO.BT_HMAC_HEADER_SIZE
     - IO.BT_TYPE_HEADER_SIZE - DATA_ENTRY_SIZE;

   type Wallet_Entry_Index is new Positive;

   function Hash (Value : in Wallet_Entry_Index) return Ada.Containers.Hash_Type;

   type Wallet_Entry;
   type Wallet_Entry_Access is access all Wallet_Entry;

   type Wallet_Directory_Entry;
   type Wallet_Directory_Entry_Access is access Wallet_Directory_Entry;

   type Wallet_Block_Entry;
   type Wallet_Block_Entry_Access is access Wallet_Block_Entry;

   --  Describe a fragment of data stored in a data block.
   type Wallet_Block_Fragment is record
      Next_Fragment : Wallet_Block_Entry_Access;
      Item          : Wallet_Entry_Access;
      Block_Offset  : IO.Block_Index := IO.Block_Index'First;
      Size          : IO.Block_Index := IO.Block_Index'First;
      Data_Offset   : Stream_Element_Offset := 0;
   end record;

   type Fragment_Count is new Natural range 0 .. 16;

   subtype Fragment_Index is Fragment_Count range 1 .. 16;

   type Fragment_Array is array (Fragment_Index) of Wallet_Block_Fragment;

   type Wallet_Block_Entry is record
      Block      : Keystore.IO.Block_Number;
      Available  : Stream_Element_Offset := IO.Block_Index'Last - IO.BT_DATA_START - 4;
      Last_Pos   : IO.Block_Index := IO.BT_DATA_START + 4;
      Data_Start : IO.Block_Index := IO.Block_Index'Last;
      Count      : Fragment_Count := 0;
      Ready      : Boolean := False;
      Fragments  : Fragment_Array;
   end record;

   type Wallet_Directory_Entry is record
      Block      : Keystore.IO.Block_Number;
      Available  : Stream_Element_Offset := IO.Block_Index'Last - IO.BT_DATA_START - 4;
      Last_Pos   : IO.Block_Index := IO.BT_DATA_START + 4;
      First      : Wallet_Entry_Access;
      Next_Block : Interfaces.Unsigned_32 := 0;
      Count      : Natural := 0;
      Ready      : Boolean := False;
   end record;

   type Wallet_Entry (Length : Natural) is limited record
      --  The block header that contains this entry.
      Header       : Wallet_Directory_Entry_Access;
      Next_Entry   : Wallet_Entry_Access;
      Entry_Offset : IO.Block_Index := IO.Block_Index'First;

      --  The block data that contains the entry content.
      Data         : Wallet_Block_Entry_Access;

      Id           : Wallet_Entry_Index;
      Size         : Interfaces.Unsigned_64 := 0;
      Kind         : Entry_Type := T_INVALID;
      Create_Date  : Ada.Calendar.Time;
      Update_Date  : Ada.Calendar.Time;
      Access_Date  : Ada.Calendar.Time;
      Block        : IO.Block_Count := 0;
      Name         : aliased String (1 .. Length);
   end record;

   package Wallet_Directory_List is
     new Ada.Containers.Doubly_Linked_Lists (Element_Type => Wallet_Directory_Entry_Access,
                                             "="          => "=");

   package Wallet_Block_Maps is
     new Ada.Containers.Ordered_Maps (Key_Type      => IO.Block_Number,
                                      Element_Type  => Wallet_Block_Entry_Access,
                                      "<" => IO."<");

   package Wallet_Maps is
     new Ada.Containers.Indefinite_Hashed_Maps (Key_Type        => String,
                                                Element_Type    => Wallet_Entry_Access,
                                                Hash            => Ada.Strings.Hash,
                                                Equivalent_Keys => "=",
                                                "="             => "=");

   package Wallet_Indexs is
     new Ada.Containers.Indefinite_Hashed_Maps (Key_Type        => Wallet_Entry_Index,
                                                Element_Type    => Wallet_Entry_Access,
                                                Hash            => Hash,
                                                Equivalent_Keys => "=",
                                                "="             => "=");

   type Wallet_Worker_Access is access all Keystore.Repository.Data.Wallet_Worker;

   type Wallet_Repository is limited new Ada.Finalization.Limited_Controlled with record
      Id             : Wallet_Identifier;
      Next_Id        : Wallet_Entry_Index;
      Data_List      : Wallet_Block_Maps.Map;
      Entry_List     : Wallet_Directory_List.List;
      Randomize      : Boolean := False;
      Root           : IO.Block_Number;
      IV             : Util.Encoders.AES.Word_Block_Type;
      Config         : Keystore.Keys.Wallet_Config;
      Map            : Wallet_Maps.Map;
      Entry_Indexes  : Wallet_Indexs.Map;
      Random         : Keystore.Random.Generator;
      Buffer         : IO.Marshaller;
      Workers        : Wallet_Worker_Access;
   end record;

   --  Delete the value associated with the given name.
   --  Raises the Not_Found exception if the name was not found.
--   procedure Delete (Manager    : in out Wallet_Repository;
--                     Name       : in String;
--                     Stream     : in out IO.Wallet_Stream'Class);

   overriding
   procedure Finalize (Manager    : in out Wallet_Repository);

end Keystore.Repository;
