-----------------------------------------------------------------------
--  keystore-metadata -- Metadata management for the keystore
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
with Util.Encoders.SHA256;
with Keystore.IO;
with Ada.Streams;
with Keystore.Keys;
private with Interfaces;
private with Util.Refs;
private with Ada.Finalization;
private with Ada.Containers.Indefinite_Hashed_Maps;
private with Ada.Containers.Doubly_Linked_Lists;
private with Ada.Strings.Hash;
private with Keystore.Random;
private package Keystore.Metadata is

   type Wallet_Repository is tagged private;

   --  Set the key to encrypt and decrypt the container meta data.
   procedure Set_Key (Repository : in out Wallet_Repository;
                      Secret     : in Secret_Key);

   --  Open the wallet repository by reading the meta data block header from the wallet
   --  IO stream.  The wallet meta data is decrypted using AES-CTR using the given secret
   --  key and initial vector.
   procedure Open (Repository : in out Wallet_Repository;
                   Password   : in Secret_Key;
                   Ident      : in Wallet_Identifier;
                   Block      : in Keystore.IO.Block_Number;
                   Keys       : in out Keystore.Keys.Key_Manager;
                   Stream     : in out IO.Wallet_Stream'Class);

   procedure Create (Repository : in out Wallet_Repository;
                     Password   : in Secret_Key;
                     Block      : in IO.Block_Number;
                     Ident      : in Wallet_Identifier;
                     Keys       : in out Keystore.Keys.Key_Manager;
                     Stream     : in out IO.Wallet_Stream'Class);

   procedure Add (Repository : in out Wallet_Repository;
                  Name       : in String;
                  Password   : in Secret_Key;
                  Wallet     : out Wallet_Repository'Class;
                  Stream     : in out IO.Wallet_Stream'Class);

   procedure Add (Repository : in out Wallet_Repository;
                  Name       : in String;
                  Kind       : in Entry_Type;
                  Content    : in Ada.Streams.Stream_Element_Array;
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

   --  Get the list of entries contained in the wallet.
   procedure List (Repository : in out Wallet_Repository;
                   Content    : out Entry_Map;
                   Stream     : in out IO.Wallet_Stream'Class);

private

   use Ada.Streams;

   function AES_Align (Size : in Stream_Element_Offset) return Stream_Element_Offset
     renames Util.Encoders.AES.Align;

   ET_WALLET_ENTRY      : constant := 16#0001#;
   ET_STRING_ENTRY      : constant := 16#0010#;
   ET_BINARY_ENTRY      : constant := 16#0200#;

   WH_KEY_SIZE          : constant := 256;
   WALLET_ENTRY_SIZE    : constant := 4 + 2 + 8 + 32 + 16 + 4;

   type Wallet_Entry_Index is new Positive;

   function Hash (Value : in Wallet_Entry_Index) return Ada.Containers.Hash_Type;

   type Wallet_Entry;
   type Wallet_Entry_Access is access all Wallet_Entry;

   type Wallet_Block_Entry is record
      Block      : Keystore.IO.Block_Number;
      First      : Wallet_Entry_Access;
      Next_Block : Interfaces.Unsigned_32 := 0;
      Available  : IO.Block_Index := IO.Block_Index'Last - IO.BT_DATA_START - 4;
      Data_Start : IO.Block_Index := IO.Block_Index'Last;
      Last_Pos   : IO.Block_Index := IO.BT_DATA_START + 4;
      Count      : Natural := 0;
      Ready      : Boolean := False;
   end record;

   type Safe_Wallet_Repository;
   type Safe_Wallet_Repository_Access is access all Safe_Wallet_Repository;

   type Wallet_Block_Entry_Access is access Wallet_Block_Entry;

   type Wallet_Entry (Length : Natural) is limited record
      --  The block header that contains this entry.
      Header       : Wallet_Block_Entry_Access;
      Next_Entry   : Wallet_Entry_Access;
      Entry_Offset : IO.Block_Index := IO.Block_Index'First;

      --  The block data that contains the entry content.
      Data         : Wallet_Block_Entry_Access;
      Next_Data    : Wallet_Entry_Access;

      --  The data offset within the data block (aligned on 16-byte).
      Data_Offset  : IO.Block_Index := IO.Block_Index'First;
      Id           : Wallet_Entry_Index;
      Size         : Interfaces.Unsigned_64 := 0;
      Kind         : Entry_Type := T_INVALID;
      Create_Date  : Ada.Calendar.Time;
      Update_Date  : Ada.Calendar.Time;
      Access_Date  : Ada.Calendar.Time;
      IV           : Util.Encoders.AES.Word_Block_Type;
      Hash         : Util.Encoders.SHA256.Hash_Array := (others => 0);
      Key          : Util.Encoders.Secret_Key (Util.Encoders.AES.AES_256_Length);
      Wallet       : Safe_Wallet_Repository_Access;
      Block        : IO.Block_Count := 0;
      Name         : aliased String (1 .. Length);
   end record;

   package Wallet_Block_List is
     new Ada.Containers.Doubly_Linked_Lists (Element_Type => Wallet_Block_Entry_Access,
                                             "="          => "=");

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

   type Wallet_Manager is limited record
      Id            : Wallet_Identifier;
      Next_Id       : Wallet_Entry_Index;
      Data_List     : Wallet_Block_List.List;
      Entry_List    : Wallet_Block_List.List;
      Root          : IO.Block_Number;
      IV            : Util.Encoders.AES.Word_Block_Type;
      Decipher      : Util.Encoders.AES.Decoder;
      Cipher        : Util.Encoders.AES.Encoder;
      Map           : Wallet_Maps.Map;
      Entry_Indexes : Wallet_Indexs.Map;
      Sign          : Util.Encoders.SHA256.Hash_Array := (others => 0);
      Protect_Key   : Secret_Key (Length => Util.Encoders.AES.AES_256_Length);
      Random        : Keystore.Random.Generator;
      Buffer        : IO.Marshaller;
   end record;

   --  Load the wallet directory block in the wallet manager buffer.
   --  Extract the directory if this is the first time the data block is read.
   procedure Load_Directory (Manager   : in out Wallet_Manager;
                             Dir_Block : in Wallet_Block_Entry_Access;
                             Stream    : in out IO.Wallet_Stream'Class);

   --  Load the complete wallet directory by starting at the given block.
   procedure Load_Complete_Directory (Manager : in out Wallet_Manager;
                                      Block   : in Keystore.IO.Block_Number;
                                      Stream  : in out IO.Wallet_Stream'Class);

   --  Find and load a directory block to hold a new entry that occupies the given space.
   --  The first directory block that has enough space is used otherwise a new block
   --  is allocated and initialized.
   procedure Find_Directory_Block (Manager     : in out Wallet_Manager;
                                   Space       : in IO.Block_Index;
                                   Entry_Block : out Wallet_Block_Entry_Access;
                                   Stream      : in out IO.Wallet_Stream'Class);

   --  Load the data block in the wallet manager buffer.  Extract the data descriptors
   --  the first time the data block is read.
   procedure Load_Data (Manager    : in out Wallet_Manager;
                        Data_Block : in Wallet_Block_Entry_Access;
                        Stream     : in out IO.Wallet_Stream'Class) with
     Pre => Data_Block.Count > 0;

   --  Add a new entry in the wallet directory.
   procedure Add_Entry (Manager : in out Wallet_Manager;
                        Name    : in String;
                        Kind    : in Entry_Type;
                        Size    : in Interfaces.Unsigned_64;
                        Item    : out Wallet_Entry_Access;
                        Stream  : in out IO.Wallet_Stream'Class);

   --  Add in the data block the wallet data entry with its content.
   --  64 + AES_Align (Content'Length) <= Data_Block.Available
   procedure Add_Data (Manager    : in out Wallet_Manager;
                       Data_Block : in out Wallet_Block_Entry;
                       Item       : in Wallet_Entry_Access;
                       Content    : in Ada.Streams.Stream_Element_Array;
                       Stream     : in out IO.Wallet_Stream'Class) with
     Pre => 64 + AES_Align (Content'Length) <= Data_Block.Available;

   protected type Safe_Wallet_Repository is

      procedure Set_Key (Secret     : in Secret_Key);

      procedure Open (Password   : in Secret_Key;
                      Ident      : in Wallet_Identifier;
                      Block      : in Keystore.IO.Block_Number;
                      Keys       : in out Keystore.Keys.Key_Manager;
                      Stream     : in out IO.Wallet_Stream'Class);

      procedure Create (Password : in Secret_Key;
                        Ident    : in Wallet_Identifier;
                        Block    : in IO.Block_Number;
                        Keys     : in out Keystore.Keys.Key_Manager;
                        Stream   : in out IO.Wallet_Stream'Class);

      procedure Add (Name     : in String;
                     Password : in Secret_Key;
                     Wallet   : out Wallet_Repository'Class;
                     Stream   : in out IO.Wallet_Stream'Class);

      procedure Add (Name       : in String;
                     Kind       : in Entry_Type;
                     Content    : in Ada.Streams.Stream_Element_Array;
                     Stream     : in out IO.Wallet_Stream'Class);

      procedure Delete (Name       : in String;
                        Stream     : in out IO.Wallet_Stream'Class);

      procedure Find (Name       : in String;
                      Result     : out Entry_Info;
                      Stream     : in out IO.Wallet_Stream'Class);

      procedure Get_Data (Name       : in String;
                          Result     : out Entry_Info;
                          Output     : out Ada.Streams.Stream_Element_Array;
                          Stream     : in out IO.Wallet_Stream'Class);

      function Contains (Name : in String) return Boolean;

      procedure List (Content    : out Entry_Map;
                      Stream     : in out IO.Wallet_Stream'Class);

      procedure Release;

   private
      Manager       : Wallet_Manager;
      Parent        : Safe_Wallet_Repository_Access;
      Self          : Safe_Wallet_Repository_Access;
   end Safe_Wallet_Repository;

   package Refs is
     new Util.Refs.General_References (Element_Type   => Safe_Wallet_Repository,
                                       Element_Access => Safe_Wallet_Repository_Access);

   type Wallet_Repository is new Refs.Ref with null record;

end Keystore.Metadata;
