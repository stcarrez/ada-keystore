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

with Ada.Text_IO;
with Ada.Directories;
with Util.Test_Caller;
with Util.Encoders.AES;
with Util.Log.Loggers;
with Util.Processes;
with Util.Streams.Buffered;
with Util.Streams.Pipes;
package body Keystore.GPG_Tests is

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Keystore.GPG_Tests");

   TEST_TOOL_PATH  : constant String := "regtests/result/test-gpg-1.akt";
   TEST_TOOL2_PATH : constant String := "regtests/result/test-gpg-2.akt";
   TEST_TOOL3_PATH : constant String := "regtests/result/test-gpg-3.akt";

   type User_Type is (User_1, User_2, User_3);

   function Tool (User : in User_Type) return String;

   package Caller is new Util.Test_Caller (Test, "AKT.GPG");

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite) is
   begin
      Caller.Add_Test (Suite, "Test AKT.Commands.Create (GPG)",
                       Test_Create'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Create (GPG++)",
                       Test_Create_Multi_User'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Info (GPG)",
                       Test_Info'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Password (GPG)",
                       Test_Add_Password'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Password.Remove (GPG)",
                       Test_Remove_Password'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Store (Update)",
                       Test_Update_File'Access);
   end Add_Tests;

   --  ------------------------------
   --  Get the tool command for a given user
   --  ------------------------------
   function Tool (User : in User_Type) return String is
      Path   : constant String := Util.Tests.Get_Test_Path ("regtests/files/gnupg/");
   begin
      case User is
         when User_1 =>
            return "bin/akt --config " & Path & "user1-akt.properties";

         when User_2 =>
            return "bin/akt --config " & Path & "user2-akt.properties";

         when User_3 =>
            return "bin/akt --config " & Path & "user3-akt.properties";

      end case;
   end Tool;

   --  ------------------------------
   --  Execute the command and get the output in a string.
   --  ------------------------------
   procedure Execute (T       : in out Test;
                      Command : in String;
                      Result  : out Ada.Strings.Unbounded.Unbounded_String;
                      Status  : in Natural := 0) is
      P        : aliased Util.Streams.Pipes.Pipe_Stream;
      Buffer   : Util.Streams.Buffered.Input_Buffer_Stream;
   begin
      Log.Info ("Execute: {0}", Command);
      P.Open (Command, Util.Processes.READ_ALL);

      --  Write on the process input stream.
      Result := Ada.Strings.Unbounded.Null_Unbounded_String;
      Buffer.Initialize (P'Unchecked_Access, 8192);
      Buffer.Read (Result);
      P.Close;
      Ada.Text_IO.Put_Line (Ada.Strings.Unbounded.To_String (Result));
      Log.Info ("Command result: {0}", Result);
      Util.Tests.Assert_Equals (T, Status, P.Get_Exit_Status, "Command '" & Command & "' failed");
   end Execute;

   procedure Execute (T       : in out Test;
                      Command : in String;
                      Expect  : in String;
                      Status  : in Natural := 0) is
      Path   : constant String := Util.Tests.Get_Test_Path ("regtests/expect/" & Expect);
      Output : constant String := Util.Tests.Get_Test_Path ("regtests/result/" & Expect);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Command & " > " & Output, Result, Status);

      Util.Tests.Assert_Equal_Files (T, Path, Output, "Command '" & Command & "' invalid output");
   end Execute;

   --  ------------------------------
   --  Test the akt keystore creation.
   --  ------------------------------
   procedure Test_Create (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path (TEST_TOOL_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      if Ada.Directories.Exists (Path) then
         Ada.Directories.Delete_File (Path);
      end if;

      --  Create keystore
      T.Execute (Tool (User_1) & " create -k " & Path & " --gpg akt-user1@ada-unit-test.org",
                 Result);
      T.Assert (Ada.Directories.Exists (Path),
                "Keystore file does not exist");

      --  List content => empty result
      T.Execute (Tool (User_1) & " list -k " & Path, Result);
      Util.Tests.Assert_Equals (T, "", Result, "list command failed");

      --  Set property
      T.Execute (Tool (User_1) & " set -k " & Path & " testing my-testing-value", Result);
      Util.Tests.Assert_Equals (T, "", Result, "set command failed");

      --  Get property
      T.Execute (Tool (User_1) & " get -k " & Path & " testing", Result);
      Util.Tests.Assert_Matches (T, "^my-testing-value", Result, "get command failed");

      --  List content => one entry
      T.Execute (Tool (User_1) & " list -k " & Path, Result);
      Util.Tests.Assert_Matches (T, "^testing", Result, "list command failed");

      --  Open keystore with another user GPG configuration should fail
      T.Execute (Tool (User_2) & " list -k " & Path, Result, 1);
      Util.Tests.Assert_Matches (T, "^Invalid password to unlock the keystore file",
                                 Result, "list command failed");

   end Test_Create;

   --  ------------------------------
   --  Test the akt keystore for several users each having their own GPG key.
   --  ------------------------------
   procedure Test_Create_Multi_User (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path (TEST_TOOL2_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      if Ada.Directories.Exists (Path) then
         Ada.Directories.Delete_File (Path);
      end if;

      --  Create keystore
      T.Execute (Tool (User_1) & " create -k " & Path & " --gpg akt-user1@ada-unit-test.org " &
                 "akt-user2@ada-unit-test.org akt-user3@ada-unit-test.org",
                 Result);
      T.Assert (Ada.Directories.Exists (Path),
                "Keystore file does not exist");

      --  List content => empty result
      for User in User_Type'Range loop
         T.Execute (Tool (User) & " list -k " & Path, Result);
         Util.Tests.Assert_Equals (T, "", Result,
                                   "list command failed for " & User_Type'Image (User));
      end loop;

      --  Set property
      T.Execute (Tool (User_1) & " set -k " & Path & " testing my-testing-value", Result);
      Util.Tests.Assert_Equals (T, "", Result, "set command failed");

      --  Get property
      for User in User_Type'Range loop
         T.Execute (Tool (User) & " get -k " & Path & " testing", Result);
         Util.Tests.Assert_Matches (T, "^my-testing-value", Result,
                                    "get command failed for " & User_Type'Image (User));
      end loop;

      --  List content => one entry
      for User in User_Type'Range loop
         T.Execute (Tool (User) & " list -k " & Path, Result);
         Util.Tests.Assert_Matches (T, "^testing", Result,
                                    "list command failed for " & User_Type'Image (User));
      end loop;
   end Test_Create_Multi_User;

   --  ------------------------------
   --  Test the akt info command on the GPG protected keystore.
   --  ------------------------------
   procedure Test_Info (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path (TEST_TOOL2_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      --  Get info about the keystore file.
      for User in User_Type'Range loop
         T.Execute (Tool (User) & " info -k " & Path, Result);

         Util.Tests.Assert_Matches (T, " 1 Kind.*2.*[0-9]+ .* [0-9A-F]+", Result,
                                    "info command failed for " & User_Type'Image (User));
         Util.Tests.Assert_Matches (T, " 2 Kind.*2.*[0-9]+ .* [0-9A-F]+", Result,
                                    "info command failed for " & User_Type'Image (User));
         Util.Tests.Assert_Matches (T, " 3 Kind.*2.*[0-9]+ .* [0-9A-F]+", Result,
                                    "info command failed for " & User_Type'Image (User));
         Util.Tests.Assert_Matches (T, "Entry count: +1", Result,
                                    "invalid number of entries for " &
                                      User_Type'Image (User));
         Util.Tests.Assert_Matches (T, "Key slots used: *1 2 3", Result,
                                    "invalid number of used key slots for " &
                                      User_Type'Image (User));
      end loop;
   end Test_Info;

   --  ------------------------------
   --  Test the akt password-add command to add a GPG key to a keystore.
   --  ------------------------------
   procedure Test_Add_Password (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path (TEST_TOOL3_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      if Ada.Directories.Exists (Path) then
         Ada.Directories.Delete_File (Path);
      end if;

      --  Create keystore with a password
      T.Execute (Tool (User_1) & " create " & Path & " -p gpg-admin -c 10:100",
                 Result);
      T.Assert (Ada.Directories.Exists (Path),
                "Keystore file does not exist");

      --  Add GPG password for User_2
      T.Execute (Tool (User_2) & " password-add " & Path &
                   " -p gpg-admin --gpg akt-user2@ada-unit-test.org",
                 Result);

      --  Set property from User_2
      T.Execute (Tool (User_2) & " set " & Path & " testing akt-user2-value", Result);
      Util.Tests.Assert_Equals (T, "", Result, "set command failed");

      --  Set property from User_1
      T.Execute (Tool (User_2) & " set " & Path & " -p gpg-admin testing2 akt-user1-value",
                 Result);
      Util.Tests.Assert_Equals (T, "", Result, "set command failed");

   end Test_Add_Password;

   --  ------------------------------
   --  Test the akt password-remove command to remove a GPG key from the keystore.
   --  ------------------------------
   procedure Test_Remove_Password (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path (TEST_TOOL3_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      Test_Add_Password (T);

      --  Remove GPG key for user2
      T.Execute (Tool (User_1) & " password-remove " & Path & " -p gpg-admin --slot 2",
                 Result);

      --  User_2 must not have access to the keystore
      T.Execute (Tool (User_2) & " get " & Path & " testing2",
                 Result, 1);
      Util.Tests.Assert_Matches (T, "^Invalid password to unlock the keystore file",
                                 Result, "get command returned unexpected result");

      --  Try remove current key
      T.Execute (Tool (User_1) & " password-remove " & Path & " -p gpg-admin --slot 1",
                 Result, 1);
      Util.Tests.Assert_Matches (T, "^Refusing to erase the key slot",
                                 Result, "password-remove command returned unexpected result");

      T.Execute (Tool (User_1) & " password-remove " & Path & " -p gpg-admin --slot 0",
                 Result, 1);
      Util.Tests.Assert_Matches (T, "^Invalid key slot number",
                                 Result, "password-remove command returned unexpected result");

      --  Add again GPG password for User_2
      T.Execute (Tool (User_2) & " password-add " & Path &
                   " -p gpg-admin --gpg akt-user2@ada-unit-test.org",
                 Result);

   end Test_Remove_Password;

   --  ------------------------------
   --  Test update content with store command
   --  ------------------------------
   procedure Test_Update_File (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path (TEST_TOOL2_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool (User_2) & " store " & Path & " LICENSE.txt",
                 Result);

      T.Execute (Tool (User_2) & " store " & Path & " -- LICENSE.txt < configure",
                 Result);

      T.Execute (Tool (User_2) & " store " & Path & " -- LICENSE.txt < Makefile",
                 Result);

      T.Execute (Tool (User_2) & " store " & Path & " -- LICENSE.txt < bin/akt",
                 Result);

      T.Execute (Tool (User_2) & " store " & Path & " -- LICENSE.txt < Makefile.conf",
                 Result);

   end Test_Update_File;

end Keystore.GPG_Tests;
