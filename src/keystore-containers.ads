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
with Keystore.Keys;
with Keystore.Repository;

private package Keystore.Containers is

   --  The `Wallet_Container` protects concurrent accesses to the repository.
   protected type Wallet_Container is

      procedure Open (Password      : in Secret_Key;
                      Ident         : in Wallet_Identifier;
                      Block         : in Keystore.IO.Block_Number;
                      Wallet_Stream : in out Keystore.IO.Refs.Stream_Ref);

      procedure Create (Password      : in Secret_Key;
                        Block         : in IO.Block_Number;
                        Ident         : in Wallet_Identifier;
                        Wallet_Stream : in out IO.Refs.Stream_Ref);

      function Get_State return State_Type;

      procedure Set_Key (Secret : in Secret_Key);

      function Contains (Name   : in String) return Boolean;

      procedure Add (Name    : in String;
                     Kind    : in Entry_Type;
                     Content : in Ada.Streams.Stream_Element_Array);

      procedure Set (Name    : in String;
                     Kind    : in Entry_Type;
                     Content : in Ada.Streams.Stream_Element_Array);

      procedure Set (Name    : in String;
                     Kind    : in Entry_Type;
                     Input   : in out Util.Streams.Input_Stream'Class);

      procedure Update (Name    : in String;
                        Kind    : in Entry_Type;
                        Content : in Ada.Streams.Stream_Element_Array);

      function Find (Name   : in String) return Entry_Info;

      procedure Get_Data (Name       : in String;
                          Result     : out Entry_Info;
                          Output     : out Ada.Streams.Stream_Element_Array);

      procedure Write (Name      : in String;
                       Output    : in out Util.Streams.Output_Stream'Class);

      procedure Delete (Name     : in String);

      procedure List (Content    : out Entry_Map);

      procedure Close;

   private
      Stream     : Keystore.IO.Refs.Stream_Ref;
      Repository : Keystore.Repository.Wallet_Repository;
      State      : State_Type := S_INVALID;
   end Wallet_Container;

end Keystore.Containers;
