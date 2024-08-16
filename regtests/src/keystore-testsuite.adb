-----------------------------------------------------------------------
--  keystore-testsuite -- Testsuite for keystore
--  Copyright (C) 2019, 2020 Stephane Carrez
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
