-----------------------------------------------------------------------
--  keystore-containers -- Container protected keystore
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
with Util.Streams;
with Ada.Streams;
with Keystore.IO.Refs;
with Keystore.Passwords;
with Keystore.Repository;
with Keystore.Keys;

private package Keystore.Containers is

   type Wallet_Container;

   --  The `Wallet_Container` protects concurrent accesses to the repository.
   protected type Wallet_Container is

      procedure Open (Ident         : in Wallet_Identifier;
                      Block         : in Keystore.IO.Storage_Block;
                      Wallet_Stream : in out Keystore.IO.Refs.Stream_Ref);

      procedure Open (Name             : in String;
                      Password         : in out Keystore.Passwords.Provider'Class;
                      From_Repo        : in out Keystore.Repository.Wallet_Repository;
                      From_Stream      : in out IO.Refs.Stream_Ref);

      procedure Create (Password      : in out Keystore.Passwords.Provider'Class;
                        Config        : in Wallet_Config;
                        Block         : in IO.Storage_Block;
                        Ident         : in Wallet_Identifier;
                        Wallet_Stream : in out IO.Refs.Stream_Ref);

      function Get_State return State_Type;

      procedure Set_Header_Data (Index     : in Header_Slot_Index_Type;
                                 Kind      : in Header_Slot_Type;
                                 Data      : in Ada.Streams.Stream_Element_Array);

      procedure Get_Header_Data (Index     : in Header_Slot_Index_Type;
                                 Kind      : out Header_Slot_Type;
                                 Data      : out Ada.Streams.Stream_Element_Array;
                                 Last      : out Ada.Streams.Stream_Element_Offset);

      procedure Unlock (Password  : in out Keystore.Passwords.Provider'Class;
                        Slot      : out Key_Slot);

      procedure Set_Key (Password     : in out Keystore.Passwords.Provider'Class;
                         New_Password : in out Keystore.Passwords.Provider'Class;
                         Config       : in Wallet_Config;
                         Mode         : in Mode_Type);

      procedure Remove_Key (Password : in out Keystore.Passwords.Provider'Class;
                            Slot     : in Key_Slot;
                            Force    : in Boolean);

      function Contains (Name   : in String) return Boolean;

      procedure Add (Name    : in String;
                     Kind    : in Entry_Type;
                     Content : in Ada.Streams.Stream_Element_Array);

      procedure Add (Name    : in String;
                     Kind    : in Entry_Type;
                     Input   : in out Util.Streams.Input_Stream'Class);

      procedure Create (Name        : in String;
                        Password    : in out Keystore.Passwords.Provider'Class;
                        From_Repo   : in out Keystore.Repository.Wallet_Repository;
                        From_Stream : in out IO.Refs.Stream_Ref);

      procedure Set (Name    : in String;
                     Kind    : in Entry_Type;
                     Content : in Ada.Streams.Stream_Element_Array);

      procedure Set (Name    : in String;
                     Kind    : in Entry_Type;
                     Input   : in out Util.Streams.Input_Stream'Class);

      procedure Update (Name    : in String;
                        Kind    : in Entry_Type;
                        Content : in Ada.Streams.Stream_Element_Array);

      procedure Find (Name    : in String;
                      Result  : out Entry_Info);

      procedure Get_Data (Name       : in String;
                          Result     : out Entry_Info;
                          Output     : out Ada.Streams.Stream_Element_Array);

      procedure Get_Data (Name      : in String;
                          Output    : in out Util.Streams.Output_Stream'Class);

      procedure Delete (Name     : in String);

      procedure List (Filter  : in Filter_Type;
                      Content : out Entry_Map);

      procedure List (Pattern : in GNAT.Regpat.Pattern_Matcher;
                      Filter  : in Filter_Type;
                      Content : out Entry_Map);

      procedure Get_Stats (Stats : out Wallet_Stats);

      procedure Close;

      procedure Set_Work_Manager (Workers   : in Keystore.Task_Manager_Access);

      procedure Do_Repository (Process : not null access
                                 procedure (Repo         : in out Repository.Wallet_Repository;
                                            Stream       : in out IO.Refs.Stream_Ref));

   private
      Stream       : Keystore.IO.Refs.Stream_Ref;
      Master       : Keystore.Keys.Key_Manager;
      Repository   : Keystore.Repository.Wallet_Repository;
      State        : State_Type := S_INVALID;
      Master_Block : Keystore.IO.Storage_Block;
      Master_Ident : Wallet_Identifier := Wallet_Identifier'First;
   end Wallet_Container;

   procedure Open_Wallet (Container : in out Wallet_Container;
                          Name      : in String;
                          Password  : in out Keystore.Passwords.Provider'Class;
                          Wallet    : in out Wallet_Container);

   procedure Add_Wallet (Container : in out Wallet_Container;
                         Name      : in String;
                         Password  : in out Keystore.Passwords.Provider'Class;
                         Wallet    : in out Wallet_Container);

end Keystore.Containers;
