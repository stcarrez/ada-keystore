-----------------------------------------------------------------------
--  keystore-gpg -- helpers to open keystores protected with GPG
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

with Keystore.Files;
with Keystore.Passwords.GPG;

package Keystore.GPG is

   subtype Wallet_File is Keystore.Files.Wallet_File;
   subtype Context_Type is Keystore.Passwords.GPG.Context_Type;

   --  Open the keystore file and unlock the wallet using GPG.
   --  Raises the Bad_Password exception if no key slot match an available GPG key.
   procedure Open (Container : in out Wallet_File;
                   Context   : in out Context_Type;
                   Path      : in String;
                   Data_Path : in String := "";
                   Config    : in Wallet_Config := Secure_Config) with
     Pre  => not Container.Is_Open,
     Post => Container.Is_Open;

end Keystore.GPG;
