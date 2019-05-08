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
private with Keystore.IO.Files;
private with Keystore.Containers;
package Keystore.Files is

   type Wallet_File is limited new Wallet with private;

   --  Open the keystore file using the given password.
   --  Raises the Bad_Password exception if no key slot match the password.
   procedure Open (Container : in out Wallet_File;
                   Password  : in Secret_Key;
                   Path      : in String) with
     Pre  => not Container.Is_Open,
     Post => Container.Is_Open;

   --  Create the keystore file and protect it with the given password.
   --  The key slot #1 is used.
   procedure Create (Container : in out Wallet_File;
                     Password  : in Secret_Key;
                     Path      : in String) with
     Pre  => not Container.Is_Open,
     Post => Container.Is_Open;

   --  Close the keystore file.
   procedure Close (Container : in out Wallet_File) with
     Pre  => Container.Is_Open,
     Post => not Container.Is_Open;

   --  Add in the wallet the named entry and associate it the children wallet.
   --  The children wallet meta data is protected by the container.
   --  The children wallet has its own key to protect the named entries it manages.
   procedure Add (Container : in out Wallet_File;
                  Name      : in String;
                  Password  : in Secret_Key;
                  Wallet    : in out Wallet_File'Class) with
     Pre  => Container.Is_Open and not Wallet.Is_Open,
     Post => Container.Is_Open and Wallet.Is_Open;

   --  Load from the container the named children wallet.
   procedure Open (Container : in out Wallet_File;
                   Name      : in String;
                   Password  : in Secret_Key;
                   Wallet    : in out Wallet_File'Class) with
     Pre  => Container.Is_Open and not Wallet.Is_Open,
     Post => Container.Is_Open and Wallet.Is_Open;

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
   procedure Set_Key (Container : in out Wallet_File;
                      Secret    : in Secret_Key) with
     Pre => Container.State /= S_OPEN;

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
   procedure Update (Container : in out Wallet_File;
                     Name      : in String;
                     Kind      : in Entry_Type := T_BINARY;
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
   procedure Write (Container : in out Wallet_File;
                    Name      : in String;
                    Output    : in out Util.Streams.Output_Stream'Class) with
     Pre => Container.Is_Open;

   --  Get the list of entries contained in the wallet.
   overriding
   procedure List (Container : in out Wallet_File;
                   Content   : out Entry_Map) with
     Pre => Container.Is_Open;

   overriding
   function Find (Container : in Wallet_File;
                  Name      : in String) return Entry_Info;

private

   type Wallet_File_Stream_Access is access all Keystore.IO.Files.Wallet_File_Stream;

   type Wallet_File is limited new Wallet with record
      Container  : Keystore.Containers.Wallet_Container;
   end record;

   overriding
   procedure Initialize (Wallet : in out Wallet_File);

   overriding
   procedure Finalize (Wallet : in out Wallet_File);

end Keystore.Files;
