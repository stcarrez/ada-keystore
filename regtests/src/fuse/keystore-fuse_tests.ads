-----------------------------------------------------------------------
--  keystore-fuse_tests -- Test AKT with Fuse support
--  Copyright (C) 2020, 2023 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Util.Tests;
package Keystore.Fuse_Tests is

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite);

   type Test is new Util.Tests.Test with null record;

   --  Test the akt mount command.
   procedure Test_Mount (T : in out Test);

   --  Test the akt mount and filling the keystore.
   procedure Test_Mount_Fill (T : in out Test);

   --  Test the akt mount and cleaning the keystore.
   procedure Test_Mount_Clean (T : in out Test);

   --  Test the akt mount and checking its content.
   procedure Test_Mount_Check (T : in out Test);

   --  Test the akt mount and stressing the filesystem.
   procedure Test_Mount_Stress (T : in out Test);

end Keystore.Fuse_Tests;
