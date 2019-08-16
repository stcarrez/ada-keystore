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
with Keystore.IO;
with Keystore.Keys;
with Util.Encoders;
package body Keystore.Containers is

   Header_Key : constant Secret_Key
     := Util.Encoders.Create ("If you can't give me poetry, can't you give me poetical science?");

   protected body Wallet_Container is

      procedure Open (Password      : in Secret_Key;
                      Ident         : in Wallet_Identifier;
                      Block         : in Keystore.IO.Storage_Block;
                      Wallet_Stream : in out Keystore.IO.Refs.Stream_Ref) is
         Master : Keystore.Keys.Key_Manager;
      begin
         Stream := Wallet_Stream;
         Master_Block := Block;
         Keys.Set_Header_Key (Master, Header_Key);
         Keystore.Repository.Open (Repository, Password, Ident, Block, Master, Stream.Value);
         State := S_OPEN;
      end Open;

      procedure Create (Password      : in Secret_Key;
                        Config        : in Wallet_Config;
                        Block         : in IO.Storage_Block;
                        Ident         : in Wallet_Identifier;
                        Wallet_Stream : in out IO.Refs.Stream_Ref) is
         Master : Keystore.Keys.Key_Manager;
      begin
         Stream := Wallet_Stream;
         Master_Block := Block;
         Keys.Set_Header_Key (Master, Header_Key);
         Keystore.Repository.Create (Repository, Password, Config, Block, Ident,
                                     Master, Stream.Value);
         State := S_OPEN;
      end Create;

      procedure Set_Key (Password     : in Secret_Key;
                         New_Password : in Secret_Key;
                         Config       : in Wallet_Config;
                         Mode         : in Mode_Type) is
         Master : Keystore.Keys.Key_Manager;
      begin
         Keys.Set_Header_Key (Master, Header_Key);
         Keystore.Keys.Set_Key (Master, Password, New_Password, Config, Mode,
                                Repository.Get_Identifier, Master_Block, Stream.Value.all);
      end Set_Key;

      function Get_State return State_Type is
      begin
         return State;
      end Get_State;

      function Contains (Name : in String) return Boolean is
      begin
         return Keystore.Repository.Contains (Repository, Name);
      end Contains;

      procedure Add (Name    : in String;
                     Kind    : in Entry_Type;
                     Content : in Ada.Streams.Stream_Element_Array) is
      begin
         Keystore.Repository.Add (Repository, Name, Kind, Content);
      end Add;

      procedure Add (Name    : in String;
                     Kind    : in Entry_Type;
                     Input   : in out Util.Streams.Input_Stream'Class) is
      begin
         Keystore.Repository.Add (Repository, Name, Kind, Input);
      end Add;

      procedure Set (Name    : in String;
                     Kind    : in Entry_Type;
                     Content : in Ada.Streams.Stream_Element_Array) is
      begin
         Keystore.Repository.Set (Repository, Name, Kind, Content);
      end Set;

      procedure Set (Name    : in String;
                     Kind    : in Entry_Type;
                     Input   : in out Util.Streams.Input_Stream'Class) is
      begin
         Keystore.Repository.Set (Repository, Name, Kind, Input);
      end Set;

      procedure Update (Name    : in String;
                        Kind    : in Entry_Type;
                        Content : in Ada.Streams.Stream_Element_Array) is
      begin
         Keystore.Repository.Update (Repository, Name, Kind, Content);
      end Update;

      procedure Delete (Name : in String) is
      begin
         Keystore.Repository.Delete (Repository, Name);
      end Delete;

      procedure Find (Name   : in String;
                      Result : out Entry_Info) is
      begin
         Keystore.Repository.Find (Repository, Name, Result);
      end Find;

      procedure Get_Data (Name       : in String;
                          Result     : out Entry_Info;
                          Output     : out Ada.Streams.Stream_Element_Array) is
      begin
         Keystore.Repository.Get_Data (Repository, Name, Result, Output);
      end Get_Data;

      procedure Get_Data (Name      : in String;
                          Output    : in out Util.Streams.Output_Stream'Class) is
      begin
         Keystore.Repository.Get_Data (Repository, Name, Output);
      end Get_Data;

      procedure List (Content : out Entry_Map) is
      begin
         Keystore.Repository.List (Repository, Content);
      end List;

      procedure Close is
      begin
         Keystore.Repository.Close (Repository);
         Stream := IO.Refs.Null_Ref;
         State := S_CLOSED;
      end Close;

      procedure Set_Work_Manager (Workers   : in Keystore.Task_Manager_Access) is
      begin
         Keystore.Repository.Set_Work_Manager (Repository, Workers);
      end Set_Work_Manager;

   end Wallet_Container;

end Keystore.Containers;
