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
with Util.Encoders;
with Util.Streams;
with Ada.Streams;
with Ada.Calendar;
with Ada.Containers.Indefinite_Ordered_Maps;
with Interfaces;
with GNAT.Regpat;
private with Ada.Exceptions;
private with Ada.Finalization;
private with Util.Executors;

--  == Keystore ==
--  The `Keystore` package provides operations to store information in secure wallets and
--  protect the stored information by encrypting the content.  It is necessary to know one
--  of the wallet password to access its content.  Wallets are protected by a master key
--  using AES-256 and the wallet master key is protected by a user password.  The wallet
--  defines up to 7 slots that identify a password key that is able to unlock the master key.
--  To open a wallet, it is necessary to unlock one of the 7 slots by providing the correct
--  password.  Wallet key slots are protected by the user's password and the PBKDF2-HMAC-256
--  algorithm, a random salt, a random counter and they are encrypted using AES-256.
--
--  === Creation ===
--  To create a keystore you will first declare a `Wallet_File` instance.  You will also need
--  a password that will be used to protect the wallet master key.
--
--    with Keystore.Files;
--    ...
--      WS   : Keystore.Files.Wallet_File;
--      Pass : Keystore.Secret := Keystore.Create ("There was no choice but to be pioneers");
--
--  You can then create the keystore file by using the `Create` operation:
--
--      WS.Create ("secure.akt", Pass);
--
--  === Storing ===
--  Values stored in the wallet are protected by their own encryption keys using AES-256.
--  The encryption key is generated when the value is added to the wallet by using the `Add`
--  operation.
--
--      WS.Add ("Grace Hopper", "If it's a good idea, go ahead and do it.");
--
--  The `Get` function allows to retrieve the value.  The value is decrypted only when the `Get`
--  operation is called.
--
--      Citation : constant String := WS.Get ("Grace Hopper");
--
--  The `Delete` procedure can be used to remove the value.  When the value is removed,
--  the encryption key and the data are erased.
--
--      WS.Delete ("Grace Hopper");
--
package Keystore is

   subtype Secret_Key is Util.Encoders.Secret_Key;
   subtype Key_Length is Util.Encoders.Key_Length;

   function Create (Password : in String) return Secret_Key
     renames Util.Encoders.Create;

   --  Exception raised when a keystore entry was not found.
   Not_Found     : exception;

   --  Exception raised when a keystore entry already exist.
   Name_Exist    : exception;

   --  Exception raised when the wallet cannot be opened with the given password.
   Bad_Password  : exception;

   --  Exception raised by Set_Key when there is no available free slot to add a new key.
   No_Key_Slot   : exception;

   --  Exception raised by Set_Header_Data when the slot index is out of range.
   No_Header_Slot : exception;

   --  Exception raised when trying to get/set an item which is a wallet.
   No_Content    : exception;

   --  The key slot is used (it cannot be erased unless the operation is forced).
   Used_Key_Slot : exception;

   --  Exception raised when the wallet is corrupted.
   Corrupted     : exception;

   --  Exception raised when opening the keystore and the header is invalid.
   Invalid_Keystore : exception;

   --  Exception raised when there is a configuration issue.
   Invalid_Config : exception;

   --  Invalid data block when reading the wallet.
   Invalid_Block : exception;

   --  Invalid HMAC signature when reading a block.
   Invalid_Signature : exception;

   --  Invalid storage identifier when loading a wallet data block.
   Invalid_Storage : exception;

   --  The wallet state.
   type State_Type is (S_INVALID, S_PROTECTED, S_OPEN, S_CLOSED);

   --  Identifies the type of data stored for a named entry in the wallet.
   type Entry_Type is (T_INVALID, T_STRING, T_FILE, T_DIRECTORY, T_BINARY, T_WALLET);

   type Filter_Type is array (Entry_Type) of Boolean;

   --  Defines the key operation mode.
   type Mode_Type is (KEY_ADD, KEY_REPLACE, KEY_REMOVE, KEY_REMOVE_LAST);

   --  Defines the key slot number.
   type Key_Slot is new Positive range 1 .. 7;

   --  Defines which key slot is used.
   type Key_Slot_Allocation is array (Key_Slot) of Boolean;

   type Header_Slot_Count_Type is new Natural range 0 .. 32;
   subtype Header_Slot_Index_Type is Header_Slot_Count_Type range 1 .. Header_Slot_Count_Type'Last;

   --  Header slot type is a 16-bit values that identifies the data type slot.
   type Header_Slot_Type is new Interfaces.Unsigned_16;

   SLOT_EMPTY        : constant Header_Slot_Type := 0;
   SLOT_KEY_GPG1     : constant Header_Slot_Type := 1; --  Contains key encrypted using GPG1
   SLOT_KEY_GPG2     : constant Header_Slot_Type := 2; --  Contains key encrypted using GPG2

   type UUID_Type is private;

   function To_String (UUID : in UUID_Type) return String;

   type Wallet_Info is record
      UUID          : UUID_Type;
      Header_Count  : Header_Slot_Count_Type := 0;
      Storage_Count : Natural := 0;
   end record;

   --  Information about a keystore entry.
   type Entry_Info is record
      Size        : Interfaces.Unsigned_64 := 0;
      Kind        : Entry_Type := T_INVALID;
      Create_Date : Ada.Calendar.Time;
      Update_Date : Ada.Calendar.Time;
      Block_Count : Natural := 0;
   end record;

   package Entry_Maps is
     new Ada.Containers.Indefinite_Ordered_Maps (Key_Type        => String,
                                                 Element_Type    => Entry_Info);

   subtype Entry_Map is Entry_Maps.Map;
   subtype Entry_Cursor is Entry_Maps.Cursor;

   --  Task manager to run encryption and decryption work.
   --  It can be assigned to the wallet through the `Set_Task_Manager` procedure.
   type Task_Manager (Count : Positive) is limited private;

   type Task_Manager_Access is access all Task_Manager;

   --  Start the tasks of the task manager.
   procedure Start (Manager : in Task_Manager_Access);

   --  Stop the tasks.
   procedure Stop (Manager : in Task_Manager_Access);

   --  Configuration to create or open a keystore.
   type Wallet_Config is record
      Randomize     : Boolean := True;
      Overwrite     : Boolean := False;
      Max_Counter   : Positive := 300_000;
      Min_Counter   : Positive := 100_000;
      Max_File_Size : Positive := Positive'Last;
      Storage_Count : Positive := 1;
   end record;

   --  Fast configuration but less secure.
   Unsecure_Config : constant Wallet_Config
     := (Randomize => False, Overwrite => False,
         Min_Counter => 10_000, Max_Counter => 100_000,
         Max_File_Size => Positive'Last,
         Storage_Count => 1);

   --  Slow configuration but more secure.
   Secure_Config : constant Wallet_Config
     := (Randomize => True, Overwrite => False,
         Min_Counter => 500_000, Max_Counter => 1_000_000,
         Max_File_Size => Positive'Last,
         Storage_Count => 1);

   type Wallet_Stats is record
      UUID             : UUID_Type;
      Keys             : Key_Slot_Allocation := (others => False);
      Entry_Count      : Natural := 0;
      Total_Size       : Natural := 0;
      Block_Count      : Natural := 0;
      Free_Block_Count : Natural := 0;
      Storage_Count    : Natural := 0;
   end record;

   --  The wallet base type.
   type Wallet is abstract tagged limited private;

   --  Return True if the container was configured.
   function Is_Configured (Container : in Wallet) return Boolean is abstract;

   --  Return True if the container can be accessed.
   function Is_Open (Container : in Wallet) return Boolean is abstract;

   --  Get the wallet state.
   function State (Container : in Wallet) return State_Type is abstract;

   --  Set the key to encrypt and decrypt the container meta data.
   procedure Set_Key (Container  : in out Wallet;
                      Secret     : in Secret_Key;
                      New_Secret : in Secret_Key;
                      Config     : in Wallet_Config := Secure_Config;
                      Mode       : in Mode_Type := KEY_REPLACE) is abstract with
     Pre'Class => Container.Is_Open;

   --  Return True if the container contains the given named entry.
   function Contains (Container : in Wallet;
                      Name      : in String) return Boolean is abstract with
     Pre'Class => Container.Is_Open;

   --  Add in the wallet the named entry and associate it the content.
   --  The content is encrypted in AES-CBC with a secret key and an IV vector
   --  that is created randomly for the new named entry.
   procedure Add (Container : in out Wallet;
                  Name      : in String;
                  Content   : in String) with
     Pre  => Wallet'Class (Container).Is_Open,
     Post => Wallet'Class (Container).Contains (Name);

   --  Add in the wallet the named entry and associate it the content.
   --  The content is encrypted in AES-CBC with a secret key and an IV vector
   --  that is created randomly for the new named entry.
   procedure Add (Container : in out Wallet;
                  Name      : in String;
                  Kind      : in Entry_Type := T_BINARY;
                  Content   : in Ada.Streams.Stream_Element_Array) is abstract with
     Pre'Class  => Container.Is_Open,
     Post'Class => Container.Contains (Name);

   procedure Add (Container : in out Wallet;
                  Name      : in String;
                  Kind      : in Entry_Type := T_BINARY;
                  Input     : in out Util.Streams.Input_Stream'Class) is abstract with
     Pre'Class  => Container.Is_Open,
     Post'Class => Container.Contains (Name);

   --  Add or update in the wallet the named entry and associate it the content.
   --  The content is encrypted in AES-CBC with a secret key and an IV vector
   --  that is created randomly for the new or updated named entry.
   procedure Set (Container : in out Wallet;
                  Name      : in String;
                  Kind      : in Entry_Type := T_BINARY;
                  Content   : in Ada.Streams.Stream_Element_Array) is abstract with
     Pre'Class  => Container.Is_Open,
     Post'Class => Container.Contains (Name);

   --  Add or update in the wallet the named entry and associate it the content.
   --  The content is encrypted in AES-CBC with a secret key and an IV vector
   --  that is created randomly for the new or updated named entry.
   procedure Set (Container : in out Wallet;
                  Name      : in String;
                  Content   : in String) with
     Pre  => Wallet'Class (Container).Is_Open,
     Post => Wallet'Class (Container).Contains (Name);

   procedure Set (Container : in out Wallet;
                  Name      : in String;
                  Kind      : in Entry_Type := T_BINARY;
                  Input     : in out Util.Streams.Input_Stream'Class) is abstract with
     Pre'Class  => Container.Is_Open,
     Post'Class => Container.Contains (Name);

   --  Update in the wallet the named entry and associate it the new content.
   --  The secret key and IV vectors are not changed.
   procedure Update (Container : in out Wallet;
                     Name      : in String;
                     Content   : in String) with
     Pre  => Wallet'Class (Container).Is_Open,
     Post => Wallet'Class (Container).Contains (Name);

   --  Update in the wallet the named entry and associate it the new content.
   --  The secret key and IV vectors are not changed.
   procedure Update (Container : in out Wallet;
                     Name      : in String;
                     Kind      : in Entry_Type := T_BINARY;
                     Content   : in Ada.Streams.Stream_Element_Array) is abstract with
     Pre'Class  => Container.Is_Open,
     Post'Class => Container.Contains (Name);

   --  Delete from the wallet the named entry.
   procedure Delete (Container : in out Wallet;
                     Name      : in String) is abstract with
     Pre'Class  => Container.Is_Open,
     Post'Class => not Container.Contains (Name);

   --  Get from the wallet the named entry.
   function Get (Container : in out Wallet;
                 Name      : in String) return String with
     Pre => Wallet'Class (Container).Is_Open;

   procedure Get (Container : in out Wallet;
                  Name      : in String;
                  Info      : out Entry_Info;
                  Content   : out Ada.Streams.Stream_Element_Array) is abstract with
     Pre'Class => Wallet'Class (Container).Is_Open;

   --  Write in the output stream the named entry value from the wallet.
   procedure Get (Container : in out Wallet;
                  Name      : in String;
                  Output    : in out Util.Streams.Output_Stream'Class) is abstract with
     Pre'Class => Container.Is_Open;

   --  Get the list of entries contained in the wallet that correspond to the optional filter.
   procedure List (Container : in out Wallet;
                   Filter    : in Filter_Type := (others => True);
                   Content   : out Entry_Map) is abstract with
     Pre'Class => Container.Is_Open;

   --  Get the list of entries contained in the wallet that correspond to the optiona filter
   --  and whose name matches the pattern.
   procedure List (Container : in out Wallet;
                   Pattern   : in GNAT.Regpat.Pattern_Matcher;
                   Filter    : in Filter_Type := (others => True);
                   Content   : out Entry_Map) is abstract with
     Pre'Class => Container.Is_Open;

   function Find (Container : in out Wallet;
                  Name      : in String) return Entry_Info is abstract with
     Pre'Class => Container.Is_Open;

   DEFAULT_WALLET_KEY : constant String
     := "If you can't give me poetry, can't you give me poetical science?";

private

   type UUID_Type is array (1 .. 4) of Interfaces.Unsigned_32;

   type Wallet_Identifier is new Positive;

   type Wallet_Entry_Index is new Interfaces.Unsigned_32 range 1 .. Interfaces.Unsigned_32'Last;

   type Wallet is abstract limited new Ada.Finalization.Limited_Controlled with null record;

   type Work_Type is limited interface;
   type Work_Type_Access is access all Work_Type'Class;

   procedure Execute (Work : in out Work_Type) is abstract;

   procedure Execute (Work : in out Work_Type_Access);

   procedure Error (Work : in out Work_Type_Access;
                    Ex   : in Ada.Exceptions.Exception_Occurrence);

   package Executors is
     new Util.Executors (Work_Type => Work_Type_Access,
                         Execute   => Execute,
                         Error     => Error);

   type Task_Manager (Count : Positive) is limited
   new Executors.Executor_Manager (Count) with null record;

   procedure Execute (Manager : in out Task_Manager;
                      Work    : in Work_Type_Access);

end Keystore;
