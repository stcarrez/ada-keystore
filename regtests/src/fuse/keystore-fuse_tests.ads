-----------------------------------------------------------------------
--  keystore-fuse_tests -- Test AKT with Fuse support
--  Copyright (C) 2020, 2023 Stephane Carrez
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
