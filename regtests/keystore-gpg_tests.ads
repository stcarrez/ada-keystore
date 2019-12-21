-----------------------------------------------------------------------
--  keystore-gpg_tests -- Test AKT with GPG2
--  Copyright (C) 2019 Stephane Carrez
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

with Ada.Strings.Unbounded;
with Util.Tests;
package Keystore.GPG_Tests is

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite);

   type Test is new Util.Tests.Test with null record;

   --  Test the akt keystore creation.
   procedure Test_Create (T : in out Test);

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

   procedure Execute (T       : in out Test;
                      Command : in String;
                      Input   : in String;
                      Output  : in String;
                      Result  : out Ada.Strings.Unbounded.Unbounded_String;
                      Status  : in Natural := 0);

   procedure Execute (T       : in out Test;
                      Command : in String;
                      Result  : out Ada.Strings.Unbounded.Unbounded_String;
                      Status  : in Natural := 0);

   procedure Execute (T       : in out Test;
                      Command : in String;
                      Expect  : in String;
                      Status  : in Natural := 0);

end Keystore.GPG_Tests;
