-----------------------------------------------------------------------
--  keystore-files -- Ada keystore files
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
with Ada.Unchecked_Deallocation;
with Util.Encoders.AES;
with Util.Log.Loggers;
package body Keystore.Files is

   procedure Free is
     new Ada.Unchecked_Deallocation (Object => IO.Files.Wallet_File_Stream,
                                     Name   => Wallet_File_Stream_Access);

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Keystore.Keys");

   --  ------------------------------
   --  Open the keystore file using the given password.
   --  Raises the Bad_Password exception if no key slot match the password.
   --  ------------------------------
   procedure Open (Container : in out Wallet_File;
                   Password  : in Secret_Key;
                   Path      : in String) is
      use IO.Files;
      Stream : IO.Files.Wallet_File_Stream_Access;
   begin
      Log.Debug ("Open keystore {0}", Path);

      Stream := new IO.Files.Wallet_File_Stream;
      Stream.Open (Path);
      Container.Container.Open (Password, 1, 1, Stream.all'Access);
      Log.Info ("Keystore {0} is opened", Path);

   exception
      when others =>
         --  Free (Stream);
         raise;
   end Open;

   --  ------------------------------
   --  Create the keystore file and protect it with the given password.
   --  The key slot #1 is used.
   --  ------------------------------
   procedure Create (Container : in out Wallet_File;
                     Password  : in Secret_Key;
                     Path      : in String) is
      Block  : IO.Block_Number;
      Stream : IO.Files.Wallet_File_Stream_Access;
   begin
      Log.Debug ("Create keystore {0}", Path);

      Stream := new IO.Files.Wallet_File_Stream;
      Stream.Create (Path);
      Stream.Allocate (Block);
      Container.Container.Create (Password, Block, 1, Stream.all'Access);
   end Create;

   --  ------------------------------
   --  Close the keystore file.
   --  ------------------------------
   procedure Close (Container : in out Wallet_File) is
   begin
      Container.Container.Close;
   end Close;

   --  Add in the wallet the named entry and associate it the children wallet.
   --  The children wallet meta data is protected by the container.
   --  The children wallet has its own key to protect the named entries it manages.
   procedure Add (Container : in out Wallet_File;
                  Name      : in String;
                  Password  : in Secret_Key;
                  Wallet    : in out Wallet_File'Class) is
   begin
      null; --  Wallet.Stream := Container.Stream;
      --  Container.Container.Add (Name, Password, Wallet.Repository);
   end Add;

   --  Load from the container the named children wallet.
   procedure Open (Container : in out Wallet_File;
                   Name      : in String;
                   Password  : in Secret_Key;
                   Wallet    : in out Wallet_File'Class) is
   begin
      null;
      --  Wallet.Stream := Container.Stream;
      --  Container.Container.Open (Name, Password, Wallet.Repository, Container.Stream.Value.all);
   end Open;

   --  ------------------------------
   --  Return True if the container was configured.
   --  ------------------------------
   overriding
   function Is_Configured (Container : in Wallet_File) return Boolean is
   begin
      return Container.Container.Get_State = S_CONFIGURED;
   end Is_Configured;

   --  ------------------------------
   --  Return True if the container can be accessed.
   --  ------------------------------
   overriding
   function Is_Open (Container : in Wallet_File) return Boolean is
   begin
      return Container.Container.Get_State = S_OPEN;
   end Is_Open;

   --  ------------------------------
   --  Get the wallet state.
   --  ------------------------------
   overriding
   function State (Container : in Wallet_File) return State_Type is
   begin
      return Container.Container.Get_State;
   end State;

   --  ------------------------------
   --  Set the key to encrypt and decrypt the container meta data.
   --  ------------------------------
   overriding
   procedure Set_Key (Container : in out Wallet_File;
                      Secret    : in Secret_Key) is
   begin
      null;
   end Set_Key;

   --  ------------------------------
   --  Return True if the container contains the given named entry.
   --  ------------------------------
   overriding
   function Contains (Container : in Wallet_File;
                      Name      : in String) return Boolean is
   begin
      return Container.Container.Contains (Name);
   end Contains;

   --  ------------------------------
   --  Add in the wallet the named entry and associate it the content.
   --  The content is encrypted in AES-CBC with a secret key and an IV vector
   --  that is created randomly for the new named entry.
   --  ------------------------------
   overriding
   procedure Add (Container : in out Wallet_File;
                  Name      : in String;
                  Kind      : in Entry_Type := T_BINARY;
                  Content   : in Ada.Streams.Stream_Element_Array) is
   begin
      Container.Container.Add (Name, Kind, Content);
   end Add;

   --  ------------------------------
   --  Add or update in the wallet the named entry and associate it the content.
   --  The content is encrypted in AES-CBC with a secret key and an IV vector
   --  that is created randomly for the new or updated named entry.
   --  ------------------------------
   overriding
   procedure Set (Container : in out Wallet_File;
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
   overriding
   procedure Set (Container : in out Wallet_File;
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
   procedure Update (Container : in out Wallet_File;
                     Name      : in String;
                     Kind      : in Entry_Type := T_BINARY;
                     Content   : in Ada.Streams.Stream_Element_Array) is
   begin
      Container.Container.Update (Name, Kind, Content);
   end Update;

   --  ------------------------------
   --  Delete from the wallet the named entry.
   --  ------------------------------
   overriding
   procedure Delete (Container : in out Wallet_File;
                     Name      : in String) is
   begin
      Container.Container.Delete (Name);
   end Delete;

   overriding
   procedure Get (Container : in out Wallet_File;
                  Name      : in String;
                  Info      : out Entry_Info;
                  Content   : out Ada.Streams.Stream_Element_Array) is
   begin
      Container.Container.Get_Data (Name, Info, Content);
   end Get;

   --  ------------------------------
   --  Write in the output stream the named entry value from the wallet.
   --  ------------------------------
   overriding
   procedure Write (Container : in out Wallet_File;
                    Name      : in String;
                    Output    : in out Util.Streams.Output_Stream'Class) is
   begin
      Container.Container.Write (Name, Output);
   end Write;

   --  ------------------------------
   --  Get the list of entries contained in the wallet.
   --  ------------------------------
   overriding
   procedure List (Container : in out Wallet_File;
                   Content   : out Entry_Map) is
   begin
      Container.Container.List (Content);
   end List;

   overriding
   function Find (Container : in Wallet_File;
                  Name      : in String) return Entry_Info is
   begin
      return Container.Container.Find (Name);
   end Find;

   overriding
   procedure Initialize (Wallet : in out Wallet_File) is
   begin
      null; --  Wallet.Container.Set_Repository (Wallet.Repository);
   end Initialize;

   overriding
   procedure Finalize (Wallet : in out Wallet_File) is
   begin
      if Wallet.Is_Open then
         Wallet.Container.Close;
      end if;
      --  if Wallet.Stream /= null then
      --    Wallet.Stream.Close;
      --  end if;
      --  Free (Wallet.Stream);
   end Finalize;

end Keystore.Files;
