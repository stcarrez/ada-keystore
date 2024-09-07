-----------------------------------------------------------------------
--  keystore-passwords-cmds -- External command based password provider
--  Copyright (C) 2019, 2020 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

package Keystore.Passwords.Cmds is

   MAX_PASSWORD_LENGTH : constant := 1024;

   --  Create a password provider that runs a command to get the password.
   function Create (Command : in String) return Provider_Access;

end Keystore.Passwords.Cmds;
