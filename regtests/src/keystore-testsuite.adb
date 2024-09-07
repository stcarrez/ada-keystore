-----------------------------------------------------------------------
--  keystore-testsuite -- Testsuite for keystore
--  Copyright (C) 2019, 2020 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Keystore.Files.Tests;
with Keystore.IO.Tests;
with Keystore.Tests;
with Keystore.Tools.Tests;
with Keystore.Passwords.Tests;
with Keystore.GPG_Tests;
with Keystore.Properties.Tests;
with Keystore.Coverage;
with Keystore.Fuse_Tests;
package body Keystore.Testsuite is

   Tests : aliased Util.Tests.Test_Suite;

   function Suite return Util.Tests.Access_Test_Suite is
   begin
      Keystore.Fuse_Tests.Add_Tests (Tests'Access);
      Keystore.Passwords.Tests.Add_Tests (Tests'Access);
      Keystore.IO.Tests.Add_Tests (Tests'Access);
      Keystore.Files.Tests.Add_Tests (Tests'Access);
      Keystore.Properties.Tests.Add_Tests (Tests'Access);
      Keystore.Tools.Tests.Add_Tests (Tests'Access);
      Keystore.Tests.Add_Tests (Tests'Access);
      Keystore.GPG_Tests.Add_Tests (Tests'Access);
      Keystore.Coverage.Add_Tests (Tests'Access);
      return Tests'Access;
   end Suite;

end Keystore.Testsuite;
