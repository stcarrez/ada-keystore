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
with Util.Encoders.AES;
with Util.Log.Loggers;
with Keystore.IO.Refs;
with Keystore.IO.Files;
package body Keystore.Files is

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Keystore.Files");

   --  ------------------------------
   --  Open the keystore file using the given password.
   --  Raises the Bad_Password exception if no key slot match the password.
   --  ------------------------------
   procedure Open (Container : in out Wallet_File;
                   Password  : in Secret_Key;
                   Path      : in String;
                   Data_Path : in String := "") is

      type Provider is new Keystore.Passwords.Provider with null record;

      overriding
      procedure Get_Password (From   : in Provider;
                              Getter : not null access procedure (Password : in Secret_Key));
      overriding
      procedure Get_Password (From   : in Provider;
                              Getter : not null access procedure (Password : in Secret_Key)) is
         pragma Unreferenced (From);
      begin
         Getter (Password);
      end Get_Password;

      Info              : Wallet_Info;
      Password_Provider : Provider;
      Slot              : Key_Slot;
   begin
      Container.Open (Path, Data_Path, Info);

      Container.Container.Unlock (Password_Provider, Slot);
      Log.Info ("Keystore {0} is opened", Path);
   end Open;

   --  ------------------------------
   --  Open the keystore file without unlocking the wallet but get some information
   --  from the header section.
   --  ------------------------------
   procedure Open (Container : in out Wallet_File;
                   Path      : in String;
                   Data_Path : in String := "";
                   Info      : out Wallet_Info) is
      use IO.Files;
      Block         : IO.Storage_Block;
      Wallet_Stream : IO.Files.Wallet_Stream_Access;
      Stream        : IO.Refs.Stream_Ref;
   begin
      Log.Debug ("Open keystore {0}", Path);

      Block.Storage := IO.DEFAULT_STORAGE_ID;
      Block.Block := 1;
      Wallet_Stream := new IO.Files.Wallet_Stream;
      Stream := IO.Refs.Create (Wallet_Stream.all'Access);
      Wallet_Stream.Open (Path, Data_Path);
      Container.Container.Open (1, Block, Stream);
      Info := Wallet_Stream.Get_Info;

      Log.Info ("Keystore {0} is opened", Path);
   end Open;

   --  ------------------------------
   --  Create the keystore file and protect it with the given password.
   --  The key slot #1 is used.
   --  ------------------------------
   procedure Create (Container : in out Wallet_File;
                     Password  : in Secret_Key;
                     Path      : in String;
                     Data_Path : in String := "";
                     Config    : in Wallet_Config := Secure_Config) is

      type Provider is new Keystore.Passwords.Provider with null record;

      overriding
      procedure Get_Password (From   : in Provider;
                              Getter : not null access procedure (Password : in Secret_Key));
      overriding
      procedure Get_Password (From   : in Provider;
                              Getter : not null access procedure (Password : in Secret_Key)) is
         pragma Unreferenced (From);
      begin
         Getter (Password);
      end Get_Password;

      Password_Provider : Provider;
   begin
      Container.Create (Password_Provider, Path, Data_Path, Config);
   end Create;

   procedure Create (Container : in out Wallet_File;
                     Password  : in out Keystore.Passwords.Provider'Class;
                     Path      : in String;
                     Data_Path : in String := "";
                     Config    : in Wallet_Config := Secure_Config) is
      Block         : IO.Storage_Block;
      Wallet_Stream : IO.Files.Wallet_Stream_Access;
      Stream        : IO.Refs.Stream_Ref;
   begin
      Log.Debug ("Create keystore {0}", Path);

      Wallet_Stream := new IO.Files.Wallet_Stream;
      Stream := IO.Refs.Create (Wallet_Stream.all'Access);

      Block.Storage := IO.DEFAULT_STORAGE_ID;
      Block.Block := 1;
      Wallet_Stream.Create (Path, Data_Path, Config);
      Wallet_Stream.Allocate (IO.MASTER_BLOCK, Block);
      Container.Container.Create (Password, Config, Block, 1, Stream);
   end Create;

   --  ------------------------------
   --  Unlock the wallet with the password.
   --  Raises the Bad_Password exception if no key slot match the password.
   --  ------------------------------
   procedure Unlock (Container : in out Wallet_File;
                     Password  : in Secret_Key) is

      type Provider is new Keystore.Passwords.Provider with null record;

      overriding
      procedure Get_Password (From   : in Provider;
                              Getter : not null access procedure (Password : in Secret_Key));
      overriding
      procedure Get_Password (From   : in Provider;
                              Getter : not null access procedure (Password : in Secret_Key)) is
         pragma Unreferenced (From);
      begin
         Getter (Password);
      end Get_Password;

      Password_Provider : Provider;
      Slot              : Key_Slot;
   begin
      Container.Container.Unlock (Password_Provider, Slot);
   end Unlock;

   procedure Unlock (Container : in out Wallet_File;
                     Password  : in out Keystore.Passwords.Provider'Class;
                     Slot      : out Key_Slot) is
   begin
      Container.Container.Unlock (Password, Slot);
   end Unlock;

   --  ------------------------------
   --  Close the keystore file.
   --  ------------------------------
   procedure Close (Container : in out Wallet_File) is
   begin
      Container.Container.Close;
   end Close;

   --  ------------------------------
   --  Set some header data in the keystore file.
   --  ------------------------------
   procedure Set_Header_Data (Container : in out Wallet_File;
                              Index     : in Header_Slot_Index_Type;
                              Kind      : in Header_Slot_Type;
                              Data      : in Ada.Streams.Stream_Element_Array) is
   begin
      Container.Container.Set_Header_Data (Index, Kind, Data);
   end Set_Header_Data;

   --  ------------------------------
   --  Get the header data information from the keystore file.
   --  ------------------------------
   procedure Get_Header_Data (Container : in out Wallet_File;
                              Index     : in Header_Slot_Index_Type;
                              Kind      : out Header_Slot_Type;
                              Data      : out Ada.Streams.Stream_Element_Array;
                              Last      : out Ada.Streams.Stream_Element_Offset) is
   begin
      Container.Container.Get_Header_Data (Index, Kind, Data, Last);
   end Get_Header_Data;

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
      return Container.Container.Get_State = S_PROTECTED;
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
   procedure Set_Key (Container    : in out Wallet_File;
                      Password     : in Secret_Key;
                      New_Password : in Secret_Key;
                      Config       : in Wallet_Config;
                      Mode         : in Mode_Type) is

      type Password_Provider is new Keystore.Passwords.Provider with null record;

      overriding
      procedure Get_Password (From   : in Password_Provider;
                              Getter : not null access procedure (Password : in Secret_Key));
      overriding
      procedure Get_Password (From   : in Password_Provider;
                              Getter : not null access procedure (Password : in Secret_Key)) is
         pragma Unreferenced (From);
      begin
         Getter (Password);
      end Get_Password;

      type New_Password_Provider is new Keystore.Passwords.Provider with null record;

      overriding
      procedure Get_Password (From   : in New_Password_Provider;
                              Getter : not null access procedure (Password : in Secret_Key));
      overriding
      procedure Get_Password (From   : in New_Password_Provider;
                              Getter : not null access procedure (Password : in Secret_Key)) is
         pragma Unreferenced (From);
      begin
         Getter (New_Password);
      end Get_Password;

      Password_P     : Password_Provider;
      New_Password_P : New_Password_Provider;
   begin
      Container.Container.Set_Key (Password_P, New_Password_P, Config, Mode);
   end Set_Key;

   procedure Set_Key (Container    : in out Wallet_File;
                      Password     : in out Keystore.Passwords.Provider'Class;
                      New_Password : in out Keystore.Passwords.Provider'Class;
                      Config       : in Wallet_Config := Secure_Config;
                      Mode         : in Mode_Type := KEY_REPLACE) is
   begin
      Container.Container.Set_Key (Password, New_Password, Config, Mode);
   end Set_Key;

   --  ------------------------------
   --  Remove the key from the key slot identified by `Slot`.  The password is necessary to
   --  make sure a valid password is available.  The `Remove_Current` must be set to remove
   --  the slot when it corresponds to the used password.
   --  ------------------------------
   procedure Remove_Key (Container : in out Wallet_File;
                         Password  : in out Keystore.Passwords.Provider'Class;
                         Slot      : in Key_Slot;
                         Force     : in Boolean) is
   begin
      Container.Container.Remove_Key (Password, Slot, Force);
   end Remove_Key;

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

   overriding
   procedure Add (Container : in out Wallet_File;
                  Name      : in String;
                  Kind      : in Entry_Type := T_BINARY;
                  Input     : in out Util.Streams.Input_Stream'Class) is
   begin
      Container.Container.Add (Name, Kind, Input);
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
   procedure Get (Container : in out Wallet_File;
                  Name      : in String;
                  Output    : in out Util.Streams.Output_Stream'Class) is
   begin
      Container.Container.Get_Data (Name, Output);
   end Get;

   --  ------------------------------
   --  Get the list of entries contained in the wallet that correspond to the optional filter.
   --  ------------------------------
   overriding
   procedure List (Container : in out Wallet_File;
                   Filter    : in Filter_Type := (others => True);
                   Content   : out Entry_Map) is
   begin
      Container.Container.List (Filter, Content);
   end List;

   --  ------------------------------
   --  Get the list of entries contained in the wallet that correspond to the optiona filter
   --  and whose name matches the pattern.
   --  ------------------------------
   procedure List (Container : in out Wallet_File;
                   Pattern   : in GNAT.Regpat.Pattern_Matcher;
                   Filter    : in Filter_Type := (others => True);
                   Content   : out Entry_Map) is
   begin
      Container.Container.List (Pattern, Filter, Content);
   end List;

   overriding
   function Find (Container : in out Wallet_File;
                  Name      : in String) return Entry_Info is
      Result : Entry_Info;
   begin
      Container.Container.Find (Name, Result);
      return Result;
   end Find;

   --  ------------------------------
   --  Get wallet file information and statistics.
   --  ------------------------------
   procedure Get_Stats (Container : in out Wallet_File;
                        Stats     : out Wallet_Stats) is
   begin
      Container.Container.Get_Stats (Stats);
   end Get_Stats;

   procedure Set_Work_Manager (Container : in out Wallet_File;
                               Workers   : in Keystore.Task_Manager_Access) is
   begin
      Container.Container.Set_Work_Manager (Workers);
   end Set_Work_Manager;

   overriding
   procedure Initialize (Wallet : in out Wallet_File) is
   begin
      null;
   end Initialize;

   overriding
   procedure Finalize (Wallet : in out Wallet_File) is
   begin
      if Wallet.Is_Open then
         Wallet.Container.Close;
      end if;
   end Finalize;

end Keystore.Files;
