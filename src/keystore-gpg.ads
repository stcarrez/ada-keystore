-----------------------------------------------------------------------
--  keystore-gpg -- helpers to open keystores protected with GPG
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
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
