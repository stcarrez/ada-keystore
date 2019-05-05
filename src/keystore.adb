-----------------------------------------------------------------------
--  keystore -- Ada keystore
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
with Keystore.Metadata;
package body Keystore is

   --  ------------------------------
   --  Return True if the container was configured.
   --  ------------------------------
   function Is_Configured (Container : in Wallet) return Boolean is
   begin
      return Container.Container.Get_State = S_CONFIGURED;
   end Is_Configured;

   --  ------------------------------
   --  Return True if the container can be accessed.
   --  ------------------------------
   function Is_Open (Container : in Wallet) return Boolean is
   begin
      return Container.Container.Get_State = S_OPEN;
   end Is_Open;

   --  ------------------------------
   --  Get the wallet state.
   --  ------------------------------
   function State (Container : in Wallet) return State_Type is
   begin
      return Container.Container.Get_State;
   end State;

   --  ------------------------------
   --  Set the key to encrypt and decrypt the container meta data.
   --  ------------------------------
   procedure Set_Key (Container : in out Wallet;
                      Secret    : in Secret_Key) is
   begin
      null;
   end Set_Key;

   --  ------------------------------
   --  Return True if the container contains the given named entry.
   --  ------------------------------
   function Contains (Container : in Wallet;
                      Name      : in String) return Boolean is
   begin
      return Container.Container.Contains (Name);
   end Contains;

   --  ------------------------------
   --  Add in the wallet the named entry and associate it the content.
   --  The content is encrypted in AES-CBC with a secret key and an IV vector
   --  that is created randomly for the new named entry.
   --  ------------------------------
   procedure Add (Container : in out Wallet;
                  Name      : in String;
                  Content   : in String) is
      use Ada.Streams;

      Data : Stream_Element_Array (Stream_Element_Offset (Content'First)
                                   .. Stream_Element_Offset (Content'Last));
      for Data'Address use Content'Address;
   begin
      Container.Container.Add (Name, T_STRING, Data);
   end Add;

   --  ------------------------------
   --  Add in the wallet the named entry and associate it the content.
   --  The content is encrypted in AES-CBC with a secret key and an IV vector
   --  that is created randomly for the new named entry.
   --  ------------------------------
   procedure Add (Container : in out Wallet;
                  Name      : in String;
                  Content   : in Ada.Streams.Stream_Element_Array) is
   begin
      Container.Container.Add (Name, T_BINARY, Content);
   end Add;

   --  ------------------------------
   --  Add or update in the wallet the named entry and associate it the content.
   --  The content is encrypted in AES-CBC with a secret key and an IV vector
   --  that is created randomly for the new or updated named entry.
   --  ------------------------------
   procedure Set (Container : in out Wallet;
                  Name      : in String;
                  Kind      : in Entry_Type := T_BINARY;
                  Content   : in Ada.Streams.Stream_Element_Array) is
   begin
      Container.Container.Set (Name, Kind, Content);
   end Set;

   --  ------------------------------
   --  Add or update in the wallet the named entry and associate it the content.
   --  The content is encrypted in AES-CBC with a secret key and an IV vector
   --  that is created randomly for the new or updated named entry.
   --  ------------------------------
   procedure Set (Container : in out Wallet;
                  Name      : in String;
                  Content   : in String) is
      use Ada.Streams;

      Data : Stream_Element_Array (Stream_Element_Offset (Content'First)
                                   .. Stream_Element_Offset (Content'Last));
      for Data'Address use Content'Address;
   begin
      Container.Container.Set (Name, T_STRING, Data);
   end Set;

   procedure Set (Container : in out Wallet;
                  Name      : in String;
                  Kind      : in Entry_Type := T_BINARY;
                  Input     : in out Util.Streams.Input_Stream'Class) is
   begin
      Container.Container.Set (Name, Kind, Input);
   end Set;

   --  ------------------------------
   --  Update in the wallet the named entry and associate it the new content.
   --  The secret key and IV vectors are not changed.
   --  ------------------------------
   procedure Update (Container : in out Wallet;
                     Name      : in String;
                     Content   : in String) is
      use Ada.Streams;

      Data : Stream_Element_Array (Stream_Element_Offset (Content'First)
                                   .. Stream_Element_Offset (Content'Last));
      for Data'Address use Content'Address;
   begin
      Container.Container.Update (Name, T_STRING, Data);
   end Update;

   --  ------------------------------
   --  Delete from the wallet the named entry.
   --  ------------------------------
   procedure Delete (Container : in out Wallet;
                     Name      : in String) is
   begin
      Container.Container.Delete (Name);
   end Delete;

   --  ------------------------------
   --  Get from the wallet the named entry.
   --  ------------------------------
   function Get (Container : in out Wallet;
                 Name      : in String) return String is
      use Ada.Streams;

      Info   : Entry_Info := Container.Container.Find (Name);
      Result : String (1 .. Info.Size);
      Buffer : Stream_Element_Array (1 .. Stream_Element_Offset (Info.Size));
      for Buffer'Address use Result'Address;
   begin
      Container.Container.Get_Data (Name, Info, Buffer);
      return Result;
   end Get;

   --  ------------------------------
   --  Write in the output stream the named entry value from the wallet.
   --  ------------------------------
   procedure Write (Container : in out Wallet;
                    Name      : in String;
                    Output    : in out Util.Streams.Output_Stream'Class) is
   begin
      Container.Container.Write (Name, Output);
   end Write;

   --  ------------------------------
   --  Get the list of entries contained in the wallet.
   --  ------------------------------
   procedure List (Container : in out Wallet;
                   Content   : out Entry_Map) is
   begin
      Container.Container.List (Content);
   end List;

   protected body Wallet_Container is

      procedure Set_Key (Secret : in Secret_Key) is
      begin
         State := S_CONFIGURED;
      end Set_Key;

      procedure Set_Repository (R : access Keystore.Metadata.Wallet_Repository) is
      begin
         Repository := R;
      end Set_Repository;

      procedure Set_Stream (S : access Keystore.IO.Wallet_Stream'Class) is
      begin
         Stream := S;
         State := S_OPEN;
      end Set_Stream;

      function Get_State return State_Type is
      begin
         return State;
      end Get_State;

      function Contains (Name : in String) return Boolean is
      begin
         return Keystore.Metadata.Contains (Repository.all, Name);
      end Contains;

      procedure Add (Name    : in String;
                     Kind    : in Entry_Type;
                     Content : in Ada.Streams.Stream_Element_Array) is
      begin
         Keystore.Metadata.Add (Repository.all, Name, Kind, Content, Stream.all);
      end Add;

      procedure Set (Name    : in String;
                     Kind    : in Entry_Type;
                     Content : in Ada.Streams.Stream_Element_Array) is
      begin
         Keystore.Metadata.Set (Repository.all, Name, Kind, Content, Stream.all);
      end Set;

      procedure Set (Name    : in String;
                     Kind    : in Entry_Type;
                     Input   : in out Util.Streams.Input_Stream'Class) is
      begin
         Keystore.Metadata.Set (Repository.all, Name, Kind, Input, Stream.all);
      end Set;

      procedure Update (Name    : in String;
                        Kind    : in Entry_Type;
                        Content : in Ada.Streams.Stream_Element_Array) is
      begin
         Keystore.Metadata.Update (Repository.all, Name, Kind, Content, Stream.all);
      end Update;

      procedure Delete (Name : in String) is
      begin
         Keystore.Metadata.Delete (Repository.all, Name, Stream.all);
      end Delete;

      function Find (Name    : in String) return Entry_Info is
         Result : Entry_Info;
      begin
         Keystore.Metadata.Find (Repository.all, Name, Result, Stream.all);
         return Result;
      end Find;

      procedure Get_Data (Name       : in String;
                          Result     : out Entry_Info;
                          Output     : out Ada.Streams.Stream_Element_Array) is
      begin
         Keystore.Metadata.Get_Data (Repository.all, Name, Result, Output, Stream.all);
      end Get_Data;

      procedure Write (Name      : in String;
                       Output    : in out Util.Streams.Output_Stream'Class) is
      begin
         Keystore.Metadata.Write (Repository.all, Name, Output, Stream.all);
      end Write;

      procedure List (Content : out Entry_Map) is
      begin
         Keystore.Metadata.List (Repository.all, Content, Stream.all);
      end List;

      procedure Close is
      begin
         Keystore.Metadata.Close (Repository.all);
         Stream := null;
         State := S_CLOSED;
      end Close;

   end Wallet_Container;

end Keystore;
