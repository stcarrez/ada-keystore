-----------------------------------------------------------------------
--  keystore-passwords-tests -- Tests for Keystore.Passwords
--  Copyright (C) 2019, 2020 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Util.Tests;
package Keystore.Passwords.Tests is

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite);

   type Test is new Util.Tests.Test with null record;

   --  Test the using the Passwords.Files
   procedure Test_File_Password (T : in out Test);

   --  Test the List_GPG_Secret_Keys against various well known formats
   procedure Test_GPG2_List_Secrets (T : in out Test);

   --  Test the List_GPG_Secret_Keys against various well known formats
   procedure Test_GPG1_List_Secrets (T : in out Test);

end Keystore.Passwords.Tests;
