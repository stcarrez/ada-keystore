-----------------------------------------------------------------------
--  keystore-passwords-input -- Interactive based password provider
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
package Keystore.Passwords.Input is

   MAX_PASSWORD_LENGTH : constant := 1024;

   --  Create a password provider that asks interactively for the password.
   function Create (Message : in String;
                    Confirm : in Boolean) return Provider_Access;

end Keystore.Passwords.Input;
