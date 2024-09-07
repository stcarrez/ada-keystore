-----------------------------------------------------------------------
--  keystore-files -- Ada keystore files
--  Copyright (C) 2019, 2020, 2022 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with Keystore.Passwords.Keys;
private with Keystore.Containers;
package Keystore.Files is

   type Wallet_File is limited new Wallet with private;

   --  Open the keystore file and unlock the wallet using the given password.
   --  Raises the Bad_Password exception if no key slot match the password.
   procedure Open (Container : in out Wallet_File;
                   Password  : in Secret_Key;
                   Path      : in String;
                   Data_Path : in String := "";
                   Config    : in Wallet_Config := Secure_Config) with
     Pre  => not Container.Is_Open,
     Post => Container.Is_Open;

   --  Open the keystore file without unlocking the wallet but get some information
   --  from the header section.
   procedure Open (Container : in out Wallet_File;
                   Path      : in String;
                   Data_Path : in String := "";
                   Config    : in Wallet_Config := Secure_Config;
                   Info      : out Wallet_Info) with
     Pre  => not Container.Is_Open,
     Post => Container.State = S_PROTECTED;

   --  Create the keystore file and protect it with the given password.
   --  The key slot #1 is used.
   procedure Create (Container : in out Wallet_File;
                     Password  : in Secret_Key;
                     Path      : in String;
                     Data_Path : in String := "";
                     Config    : in Wallet_Config := Secure_Config) with
     Pre  => not Container.Is_Open,
     Post => Container.Is_Open;

   procedure Create (Container : in out Wallet_File;
                     Password  : in out Keystore.Passwords.Provider'Class;
                     Path      : in String;
                     Data_Path : in String := "";
                     Config    : in Wallet_Config := Secure_Config) with
     Pre  => not Container.Is_Open,
     Post => Container.Is_Open;

   --  Set the keystore master key before creating or opening the keystore.
   procedure Set_Master_Key (Container : in out Wallet_File;
                             Password  : in out Keystore.Passwords.Keys.Key_Provider'Class) with
     Pre => not Container.Is_Open;

   --  Unlock the wallet with the password.
   --  Raises the Bad_Password exception if no key slot match the password.
   procedure Unlock (Container : in out Wallet_File;
                     Password  : in Secret_Key) with
     Pre  => Container.State = S_PROTECTED,
     Post => Container.Is_Open;

   procedure Unlock (Container : in out Wallet_File;
                     Password  : in out Keystore.Passwords.Provider'Class;
                     Slot      : out Key_Slot) with
     Pre  => Container.State = S_PROTECTED,
     Post => Container.Is_Open;

   --  Close the keystore file.
   procedure Close (Container : in out Wallet_File) with
     Pre  => Container.Is_Open,
     Post => not Container.Is_Open;

   --  Set some header data in the keystore file.
   procedure Set_Header_Data (Container : in out Wallet_File;
                              Index     : in Header_Slot_Index_Type;
                              Kind      : in Header_Slot_Type;
                              Data      : in Ada.Streams.Stream_Element_Array) with
     Pre => Container.State in S_OPEN | S_PROTECTED and then Data'Length <= 1024;

   --  Get the header data information from the keystore file.
   procedure Get_Header_Data (Container : in out Wallet_File;
                              Index     : in Header_Slot_Index_Type;
                              Kind      : out Header_Slot_Type;
                              Data      : out Ada.Streams.Stream_Element_Array;
                              Last      : out Ada.Streams.Stream_Element_Offset) with
     Pre => Container.State = S_PROTECTED;

   --  Add in the wallet the named entry and associate it the children wallet.
   --  The children wallet meta data is protected by the container.
   --  The children wallet has its own key to protect the named entries it manages.
   procedure Add (Container : in out Wallet_File;
                  Name      : in String;
                  Password  : in out Keystore.Passwords.Provider'Class;
                  Wallet    : in out Wallet_File'Class) with
     Pre  => Container.Is_Open and then not Wallet.Is_Open,
     Post => Container.Is_Open and then Wallet.Is_Open;

   procedure Add (Container : in out Wallet_File;
                  Name      : in String;
                  Password  : in Keystore.Secret_Key;
                  Wallet    : in out Wallet_File'Class) with
     Pre  => Container.Is_Open and then not Wallet.Is_Open,
     Post => Container.Is_Open and then Wallet.Is_Open;

   --  Load from the container the named children wallet.
   procedure Open (Container : in out Wallet_File;
                   Name      : in String;
                   Password  : in out Keystore.Passwords.Provider'Class;
                   Wallet    : in out Wallet_File'Class) with
     Pre  => Container.Is_Open and then not Wallet.Is_Open,
     Post => Container.Is_Open and then Wallet.Is_Open;

   procedure Open (Container : in out Wallet_File;
                   Name      : in String;
                   Password  : in Secret_Key;
                   Wallet    : in out Wallet_File'Class) with
     Pre  => Container.Is_Open and then not Wallet.Is_Open,
     Post => Container.Is_Open and then Wallet.Is_Open;

   --  Return True if the container was configured.
   overriding
   function Is_Configured (Container : in Wallet_File) return Boolean;

   --  Return True if the container can be accessed.
   overriding
   function Is_Open (Container : in Wallet_File) return Boolean;

   --  Get the wallet state.
   overriding
   function State (Container : in Wallet_File) return State_Type;

   --  Set the key to encrypt and decrypt the container meta data.
   overriding
   procedure Set_Key (Container    : in out Wallet_File;
                      Password     : in Secret_Key;
                      New_Password : in Secret_Key;
                      Config       : in Wallet_Config;
                      Mode         : in Mode_Type) with
     Pre => Container.Is_Open;

   procedure Set_Key (Container    : in out Wallet_File;
                      Password     : in out Keystore.Passwords.Provider'Class;
                      New_Password : in out Keystore.Passwords.Provider'Class;
                      Config       : in Wallet_Config := Secure_Config;
                      Mode         : in Mode_Type := KEY_REPLACE) with
     Pre'Class => Container.Is_Open;

   --  Remove the key from the key slot identified by `Slot`.  The password is necessary to
   --  make sure a valid password is available.  The `Remove_Current` must be set to remove
   --  the slot when it corresponds to the used password.
   procedure Remove_Key (Container : in out Wallet_File;
                         Password  : in out Keystore.Passwords.Provider'Class;
                         Slot      : in Key_Slot;
                         Force     : in Boolean);

   --  Return True if the container contains the given named entry.
   overriding
   function Contains (Container : in Wallet_File;
                      Name      : in String) return Boolean with
     Pre => Container.Is_Open;

   --  Add in the wallet the named entry and associate it the content.
   --  The content is encrypted in AES-CBC with a secret key and an IV vector
   --  that is created randomly for the new named entry.
   overriding
   procedure Add (Container : in out Wallet_File;
                  Name      : in String;
                  Kind      : in Entry_Type := T_BINARY;
                  Content   : in Ada.Streams.Stream_Element_Array) with
     Pre  => Container.Is_Open,
     Post => Container.Contains (Name);

   overriding
   procedure Add (Container : in out Wallet_File;
                  Name      : in String;
                  Kind      : in Entry_Type := T_BINARY;
                  Input     : in out Util.Streams.Input_Stream'Class) with
     Pre'Class  => Container.Is_Open,
     Post'Class => Container.Contains (Name);

   --  Add or update in the wallet the named entry and associate it the content.
   --  The content is encrypted in AES-CBC with a secret key and an IV vector
   --  that is created randomly for the new or updated named entry.
   overriding
   procedure Set (Container : in out Wallet_File;
                  Name      : in String;
                  Kind      : in Entry_Type := T_BINARY;
                  Content   : in Ada.Streams.Stream_Element_Array) with
     Pre  => Container.Is_Open,
     Post => Container.Contains (Name);

   overriding
   procedure Set (Container : in out Wallet_File;
                  Name      : in String;
                  Kind      : in Entry_Type := T_BINARY;
                  Input     : in out Util.Streams.Input_Stream'Class) with
     Pre  => Container.Is_Open,
     Post => Container.Contains (Name);

   --  Update in the wallet the named entry and associate it the new content.
   --  The secret key and IV vectors are not changed.
   overriding
   procedure Update (Container : in out Wallet_File;
                     Name      : in String;
                     Kind      : in Entry_Type := T_BINARY;
                     Content   : in Ada.Streams.Stream_Element_Array) with
     Pre  => Container.Is_Open,
     Post => Container.Contains (Name);

   --  Read from the wallet the named entry starting at the given position.
   --  Upon successful completion, Last will indicate the last valid position of
   --  the Content array.
   overriding
   procedure Read (Container : in out Wallet_File;
                   Name      : in String;
                   Offset    : in Ada.Streams.Stream_Element_Offset;
                   Content   : out Ada.Streams.Stream_Element_Array;
                   Last      : out Ada.Streams.Stream_Element_Offset) with
     Pre  => Container.Is_Open,
     Post => Container.Contains (Name);

   --  Write in the wallet the named entry starting at the given position.
   --  The existing content is overwritten or new content is appended.
   overriding
   procedure Write (Container : in out Wallet_File;
                    Name      : in String;
                    Offset    : in Ada.Streams.Stream_Element_Offset;
                    Content   : in Ada.Streams.Stream_Element_Array) with
     Pre  => Container.Is_Open,
     Post => Container.Contains (Name);

   --  Delete from the wallet the named entry.
   overriding
   procedure Delete (Container : in out Wallet_File;
                     Name      : in String) with
     Pre  => Container.Is_Open,
     Post => not Container.Contains (Name);

   overriding
   procedure Get (Container : in out Wallet_File;
                  Name      : in String;
                  Info      : out Entry_Info;
                  Content   : out Ada.Streams.Stream_Element_Array) with
     Pre => Container.Is_Open;

   --  Write in the output stream the named entry value from the wallet.
   overriding
   procedure Get (Container : in out Wallet_File;
                  Name      : in String;
                  Output    : in out Util.Streams.Output_Stream'Class) with
     Pre => Container.Is_Open;

   --  Get the list of entries contained in the wallet that correspond to the optional filter.
   overriding
   procedure List (Container : in out Wallet_File;
                   Filter    : in Filter_Type := (others => True);
                   Content   : out Entry_Map) with
     Pre => Container.Is_Open;

   --  Get the list of entries contained in the wallet that correspond to the optiona filter
   --  and whose name matches the pattern.
   overriding
   procedure List (Container : in out Wallet_File;
                   Pattern   : in GNAT.Regpat.Pattern_Matcher;
                   Filter    : in Filter_Type := (others => True);
                   Content   : out Entry_Map) with
     Pre => Container.Is_Open;

   overriding
   function Find (Container : in out Wallet_File;
                  Name      : in String) return Entry_Info;

   --  Get wallet file information and statistics.
   procedure Get_Stats (Container : in out Wallet_File;
                        Stats     : out Wallet_Stats);

   procedure Set_Work_Manager (Container : in out Wallet_File;
                               Workers   : in Keystore.Task_Manager_Access);

private

   type Wallet_File is limited new Wallet with record
      Container  : Keystore.Containers.Wallet_Container;
   end record;

   overriding
   procedure Initialize (Wallet : in out Wallet_File);

   overriding
   procedure Finalize (Wallet : in out Wallet_File);

end Keystore.Files;
