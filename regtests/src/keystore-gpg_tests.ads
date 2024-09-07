-----------------------------------------------------------------------
--  keystore-gpg_tests -- Test AKT with GPG2
--  Copyright (C) 2019, 2020, 2021, 2023 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Util.Tests;
package Keystore.GPG_Tests is

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite);

   type Test is new Util.Tests.Test with null record;

   --  Test the akt keystore creation.
   procedure Test_Create (T : in out Test);

   --  Test the akt keystore creation with missing parameter.
   procedure Test_Create_Bad_Usage (T : in out Test);

   --  Test the akt keystore for several users each having their own GPG key.
   procedure Test_Create_Multi_User (T : in out Test);

   --  Test the akt info command on the GPG protected keystore.
   procedure Test_Info (T : in out Test);

   --  Test the akt password-add command to add a GPG key to a keystore.
   procedure Test_Add_Password (T : in out Test);

   --  Test the akt password-remove command to remove a GPG key from the keystore.
   procedure Test_Remove_Password (T : in out Test);

   --  Test update content with store command
   procedure Test_Update_File (T : in out Test);

   --  Test when gpg execution fails
   procedure Test_GPG_Error (T : in out Test);

end Keystore.GPG_Tests;
