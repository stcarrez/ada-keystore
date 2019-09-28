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
with Keystore.Repository;

private package Keystore.Containers is

   --  The `Wallet_Container` protects concurrent accesses to the repository.
   protected type Wallet_Container is

      procedure Open (Ident         : in Wallet_Identifier;
                      Block         : in Keystore.IO.Storage_Block;
                      Wallet_Stream : in out Keystore.IO.Refs.Stream_Ref);

      procedure Create (Password      : in Secret_Key;
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

      procedure Unlock (Password  : in Secret_Key);

      procedure Set_Key (Password     : in Secret_Key;
                         New_Password : in Secret_Key;
                         Config       : in Wallet_Config;
                         Mode         : in Mode_Type);

      function Contains (Name   : in String) return Boolean;

      procedure Add (Name    : in String;
                     Kind    : in Entry_Type;
                     Content : in Ada.Streams.Stream_Element_Array);

      procedure Add (Name    : in String;
                     Kind    : in Entry_Type;
                     Input   : in out Util.Streams.Input_Stream'Class);

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

      procedure List (Content    : out Entry_Map);

      procedure Get_Stats (Stats : out Wallet_Stats);

      procedure Close;

      procedure Set_Work_Manager (Workers   : in Keystore.Task_Manager_Access);

   private
      Stream       : Keystore.IO.Refs.Stream_Ref;
      Repository   : Keystore.Repository.Wallet_Repository;
      State        : State_Type := S_INVALID;
      Master_Block : Keystore.IO.Storage_Block;
      Master_Ident : Wallet_Identifier;
   end Wallet_Container;

end Keystore.Containers;
