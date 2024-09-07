-----------------------------------------------------------------------
--  keystore-tools-tests -- Tests for keystore files
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Util.Tests;
package Keystore.Tools.Tests is

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite);

   type Test is new Util.Tests.Test with null record;

   --  Test storing a directory tree
   procedure Test_Store_Directory (T : in out Test);

end Keystore.Tools.Tests;
