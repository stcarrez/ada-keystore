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
private with Keystore.Metadata;
private with Keystore.IO.Files;
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

   --  Add in the wallet the named entry and associate it the children wallet.
   --  The children wallet meta data is protected by the container.
   --  The children wallet has its own key to protect the named entries it manages.
   procedure Add (Container : in out Wallet_File;
                  Name      : in String;
                  Wallet    : in out Wallet_File'Class) with
     Pre  => Container.Is_Open and not Wallet.Is_Open,
     Post => Container.Is_Open and Wallet.Is_Open;

   --  Load from the container the named children wallet.
   procedure Load (Container : in out Wallet_File;
                   Name      : in String;
                   Wallet    : in out Wallet_File'Class) with
     Pre  => Container.Is_Open and not Wallet.Is_Open,
     Post => Container.Is_Open and Wallet.Is_Open;

private

   type Wallet_File_Stream_Access is access all Keystore.IO.Files.Wallet_File_Stream;

   type Wallet_File is limited new Wallet with record
      Stream     : Wallet_File_Stream_Access;
      Repository : aliased Keystore.Metadata.Wallet_Repository;
   end record;

   overriding
   procedure Initialize (Wallet : in out Wallet_File);

   overriding
   procedure Finalize (Wallet : in out Wallet_File);

end Keystore.Files;
