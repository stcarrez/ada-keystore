-----------------------------------------------------------------------
--  keystore-files -- Ada keystore files
--  Copyright (C) 2019, 2020, 2022 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
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
                   Data_Path : in String := "";
                   Config    : in Wallet_Config := Secure_Config) is
      procedure Process (Provider : in out Keystore.Passwords.Provider'Class);

      procedure Process (Provider : in out Keystore.Passwords.Provider'Class) is
         Slot  : Key_Slot;
      begin
         Container.Container.Unlock (Provider, Slot);
      end Process;

      Info     : Wallet_Info;
   begin
      Container.Open (Path, Data_Path, Config, Info);
      Keystore.Passwords.To_Provider (Password, Process'Access);

      Log.Info ("Keystore {0} is opened", Path);
   end Open;

   --  ------------------------------
   --  Open the keystore file without unlocking the wallet but get some information
   --  from the header section.
   --  ------------------------------
   procedure Open (Container : in out Wallet_File;
                   Path      : in String;
                   Data_Path : in String := "";
                   Config    : in Wallet_Config := Secure_Config;
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
      Container.Container.Open (Config, 1, Block, Stream);
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
      procedure Process (Provider : in out Keystore.Passwords.Provider'Class);

      procedure Process (Provider : in out Keystore.Passwords.Provider'Class) is
      begin
         Container.Create (Provider, Path, Data_Path, Config);
      end Process;

   begin
      Keystore.Passwords.To_Provider (Password, Process'Access);
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
   --  Set the keystore master key before creating or opening the keystore.
   --  ------------------------------
   procedure Set_Master_Key (Container : in out Wallet_File;
                             Password  : in out Keystore.Passwords.Keys.Key_Provider'Class) is
   begin
      Container.Container.Set_Master_Key (Password);
   end Set_Master_Key;

   --  ------------------------------
   --  Unlock the wallet with the password.
   --  Raises the Bad_Password exception if no key slot match the password.
   --  ------------------------------
   procedure Unlock (Container : in out Wallet_File;
                     Password  : in Secret_Key) is
      procedure Process (Provider : in out Keystore.Passwords.Provider'Class);

      procedure Process (Provider : in out Keystore.Passwords.Provider'Class) is
         Slot  : Key_Slot;
      begin
         Container.Container.Unlock (Provider, Slot);
      end Process;

   begin
      Keystore.Passwords.To_Provider (Password, Process'Access);
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
                  Password  : in out Keystore.Passwords.Provider'Class;
                  Wallet    : in out Wallet_File'Class) is
   begin
      null;
      Keystore.Containers.Add_Wallet (Container.Container, Name, Password, Wallet.Container);
   end Add;

   procedure Add (Container : in out Wallet_File;
                  Name      : in String;
                  Password  : in Keystore.Secret_Key;
                  Wallet    : in out Wallet_File'Class) is
      procedure Process (Provider : in out Keystore.Passwords.Provider'Class);

      procedure Process (Provider : in out Keystore.Passwords.Provider'Class) is
      begin
         Container.Add (Name, Provider, Wallet);
      end Process;

   begin
      Keystore.Passwords.To_Provider (Password, Process'Access);
   end Add;

   --  Load from the container the named children wallet.
   procedure Open (Container : in out Wallet_File;
                   Name      : in String;
                   Password  : in out Keystore.Passwords.Provider'Class;
                   Wallet    : in out Wallet_File'Class) is
   begin
      Keystore.Containers.Open_Wallet (Container.Container, Name, Password, Wallet.Container);
   end Open;

   procedure Open (Container : in out Wallet_File;
                   Name      : in String;
                   Password  : in Keystore.Secret_Key;
                   Wallet    : in out Wallet_File'Class) is
      procedure Process (Provider : in out Keystore.Passwords.Provider'Class);

      procedure Process (Provider : in out Keystore.Passwords.Provider'Class) is
      begin
         Container.Open (Name, Provider, Wallet);
      end Process;

   begin
      Keystore.Passwords.To_Provider (Password, Process'Access);
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
      procedure Process (Provider : in out Keystore.Passwords.Provider'Class);

      procedure Process (Provider : in out Keystore.Passwords.Provider'Class) is
         procedure Process_New (New_Provider : in out Keystore.Passwords.Provider'Class);

         procedure Process_New (New_Provider : in out Keystore.Passwords.Provider'Class) is
         begin
            Container.Container.Set_Key (Provider, New_Provider, Config, Mode);
         end Process_New;

      begin
         Keystore.Passwords.To_Provider (New_Password, Process_New'Access);
      end Process;

   begin
      Keystore.Passwords.To_Provider (Password, Process'Access);
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
   overriding
   procedure Update (Container : in out Wallet_File;
                     Name      : in String;
                     Kind      : in Entry_Type := T_BINARY;
                     Content   : in Ada.Streams.Stream_Element_Array) is
   begin
      Container.Container.Update (Name, Kind, Content);
   end Update;

   --  ------------------------------
   --  Read from the wallet the named entry starting at the given position.
   --  Upon successful completion, Last will indicate the last valid position of
   --  the Content array.
   --  ------------------------------
   overriding
   procedure Read (Container : in out Wallet_File;
                   Name      : in String;
                   Offset    : in Ada.Streams.Stream_Element_Offset;
                   Content   : out Ada.Streams.Stream_Element_Array;
                   Last      : out Ada.Streams.Stream_Element_Offset) is
   begin
      Container.Container.Read (Name, Offset, Content, Last);
   end Read;

   --  ------------------------------
   --  Write in the wallet the named entry starting at the given position.
   --  The existing content is overwritten or new content is appended.
   --  ------------------------------
   overriding
   procedure Write (Container : in out Wallet_File;
                    Name      : in String;
                    Offset    : in Ada.Streams.Stream_Element_Offset;
                    Content   : in Ada.Streams.Stream_Element_Array) is
   begin
      Container.Container.Write (Name, Offset, Content);
   end Write;

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
   overriding
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
      Wallet.Container.Initialize;
   end Initialize;

   overriding
   procedure Finalize (Wallet : in out Wallet_File) is
   begin
      if Wallet.Is_Open then
         Wallet.Container.Close;
      end if;
   end Finalize;

end Keystore.Files;
