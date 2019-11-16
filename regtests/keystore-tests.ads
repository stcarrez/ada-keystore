-----------------------------------------------------------------------
--  keystore-tests -- Tests for keystore tool
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
package Keystore.Tests is

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite);

   type Test is new Util.Tests.Test with null record;

   --  Test the akt help command.
   procedure Test_Tool_Help (T : in out Test);

   --  Test the akt keystore creation.
   procedure Test_Tool_Create (T : in out Test);

   --  Test the akt keystore creation with password file.
   procedure Test_Tool_Create_Password_File (T : in out Test);

   --  Test the akt command adding and removing values.
   procedure Test_Tool_Set_Remove (T : in out Test);
   procedure Test_Tool_Set_Remove_2 (T : in out Test);

   --  Test the akt command setting a big file.
   procedure Test_Tool_Set_Big (T : in out Test);

   --  Test the akt get command.
   procedure Test_Tool_Get (T : in out Test);

   --  Test the akt get command with errors.
   procedure Test_Tool_Get_Error (T : in out Test);

   --  Test the akt command with invalid parameters.
   procedure Test_Tool_Invalid (T : in out Test);

   --  Test the akt edit command.
   procedure Test_Tool_Edit (T : in out Test);

   --  Test the akt store and akt extract commands.
   procedure Test_Tool_Store_Extract (T : in out Test);

   --  Test the akt password-set command.
   procedure Test_Tool_Password_Set (T : in out Test);

   --  Test the akt with an interactive password.
   procedure Test_Tool_Interactive_Password (T : in out Test);

   --  Test the akt with data blocks written in separate files.
   procedure Test_Tool_Separate_Data (T : in out Test);

   --  Test the akt config command.
   procedure Test_Tool_Set_Config (T : in out Test);

   procedure Execute (T       : in out Test;
                      Command : in String;
                      Result  : out Ada.Strings.Unbounded.Unbounded_String;
                      Status  : in Natural := 0);

   procedure Execute (T       : in out Test;
                      Command : in String;
                      Expect  : in String;
                      Status  : in Natural := 0);

   procedure Store_Extract (T       : in out Test;
                            Command : in String;
                            Name    : in String;
                            Path    : in String);

end Keystore.Tests;
