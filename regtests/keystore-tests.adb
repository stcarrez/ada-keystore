-----------------------------------------------------------------------
--  keystore-tests -- Tests for keystore IO
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
with Util.Files;
with Util.Test_Caller;
with Util.Encoders.AES;
with Util.Log.Loggers;
with Util.Processes;
with Util.Streams.Buffered;
with Util.Streams.Pipes;
package body Keystore.Tests is

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Keystore.Tool");

   function Tool return String;

   package Caller is new Util.Test_Caller (Test, "AKT");

   generic
      Command : String;
   procedure Test_Help_Command (T : in out Test);

   procedure Test_Help_Command (T : in out Test) is
   begin
      T.Execute (Tool & " help " & Command, "akt-help-" & Command & ".txt");
   end Test_Help_Command;

   procedure Test_Tool_Help_Create is new Test_Help_Command ("create");
   procedure Test_Tool_Help_Edit is new Test_Help_Command ("edit");
   procedure Test_Tool_Help_Get is new Test_Help_Command ("get");
   procedure Test_Tool_Help_List is new Test_Help_Command ("list");
   procedure Test_Tool_Help_Remove is new Test_Help_Command ("remove");
   procedure Test_Tool_Help_Set is new Test_Help_Command ("set");

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite) is
   begin
      Caller.Add_Test (Suite, "Test AKT.Commands.Help",
                       Test_Tool_Help'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Create",
                       Test_Tool_Create'Access);
      Caller.Add_Test (Suite, "Test AKT.Main",
                       Test_Tool_Invalid'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Create (password-file)",
                       Test_Tool_Create_Password_File'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Remove",
                       Test_Tool_Set_Remove'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Set",
                       Test_Tool_Set_Big'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Get",
                       Test_Tool_Get'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Create (help)",
                       Test_Tool_Help_Create'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Edit (help)",
                       Test_Tool_Help_Edit'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Get (help)",
                       Test_Tool_Help_Get'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Set (help)",
                       Test_Tool_Help_Set'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Remove (help)",
                       Test_Tool_Help_Remove'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.List (help)",
                       Test_Tool_Help_List'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Edit",
                       Test_Tool_Edit'Access);
   end Add_Tests;

   --  ------------------------------
   --  Get the dynamo executable path.
   --  ------------------------------
   function Tool return String is
   begin
      return "bin/akt";
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
   --  Test the akt help command.
   --  ------------------------------
   procedure Test_Tool_Help (T : in out Test) is
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " help", Result);
      Util.Tests.Assert_Matches (T, ".*tool to store and protect your sensitive data", Result,
                                 "Invalid help");
   end Test_Tool_Help;

   --  ------------------------------
   --  Test the akt keystore creation.
   --  ------------------------------
   procedure Test_Tool_Create (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path ("regtests/result/test-tool.akt");
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      if Ada.Directories.Exists (Path) then
         Ada.Directories.Delete_File (Path);
      end if;

      --  Create keystore
      T.Execute (Tool & " -f " & Path & " -p admin create", Result);
      Util.Tests.Assert_Equals (T, "", Result, "create command failed");
      T.Assert (Ada.Directories.Exists (Path),
                "Keystore file does not exist");

      --  List content => empty result
      T.Execute (Tool & " -f " & Path & " -p admin list", Result);
      Util.Tests.Assert_Equals (T, "", Result, "list command failed");

      --  Set property
      T.Execute (Tool & " -f " & Path & " -p admin set testing my-testing-value", Result);
      Util.Tests.Assert_Equals (T, "", Result, "set command failed");

      --  Get property
      T.Execute (Tool & " -f " & Path & " -p admin get testing", Result);
      Util.Tests.Assert_Matches (T, "^my-testing-value", Result, "get command failed");

      --  List content => one entry
      T.Execute (Tool & " -f " & Path & " -p admin list", Result);
      Util.Tests.Assert_Matches (T, "^testing", Result, "list command failed");

      --  Open keystore with invalid password
      T.Execute (Tool & " -f " & Path & " -p admin2 list", Result, 1);
      Util.Tests.Assert_Matches (T, "^ERROR: Invalid password to unlock the keystore file",
                                 Result, "list command failed");

   end Test_Tool_Create;

   --  ------------------------------
   --  Test the akt keystore creation with password file.
   --  ------------------------------
   procedure Test_Tool_Create_Password_File (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path ("regtests/result/test-tool.akt");
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      if Ada.Directories.Exists (Path) then
         Ada.Directories.Delete_File (Path);
      end if;

      --  Create keystore
      --  file.key must have rw------- mode (600)
      --  regtests/files must have rwx------ (700)
      T.Execute (Tool & " -f " & Path & " --passfile regtests/files/file.key create",
                 Result, 0);
      Util.Tests.Assert_Equals (T, "", Result, "create command failed");
      T.Assert (Ada.Directories.Exists (Path),
                "Keystore file does not exist");

      --  Set property
      T.Execute (Tool & " -f " & Path & " --passfile regtests/files/file.key "
                 & "set testing my-testing-value", Result);
      Util.Tests.Assert_Equals (T, "", Result, "set command failed");

      --  List content => one entry
      T.Execute (Tool & " -f " & Path & " --passfile regtests/files/file.key list", Result);
      Util.Tests.Assert_Matches (T, "^testing", Result, "list command failed");

   end Test_Tool_Create_Password_File;

   --  ------------------------------
   --  Test the akt command adding and removing values.
   --  ------------------------------
   procedure Test_Tool_Set_Remove (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path ("regtests/result/test-tool.akt");
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      Test_Tool_Create (T);

      --  Set property
      T.Execute (Tool & " -f " & Path & " -p admin "
                 & "set testing my-new-testing-value", Result);
      Util.Tests.Assert_Equals (T, "", Result, "set command failed");

      --  Remove property
      T.Execute (Tool & " -f " & Path & " -p admin "
                 & "remove testing", Result);
      Util.Tests.Assert_Equals (T, "", Result, "remove command failed");

   end Test_Tool_Set_Remove;

   --  ------------------------------
   --  Test the akt command setting a big file.
   --  ------------------------------
   procedure Test_Tool_Set_Big (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path ("regtests/result/test-tool.akt");
      Path2  : constant String := Util.Tests.Get_Test_Path ("regtests/result/big-content.txt");
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      Test_Tool_Create (T);

      --  Set property
      T.Execute (Tool & " -f " & Path & " -p admin "
                 & "set testing -f LICENSE.txt", Result);
      Util.Tests.Assert_Equals (T, "", Result, "set -f <file> command failed");

      --  Get the property
      T.Execute (Tool & " -f " & Path & " -p admin "
                 & "get testing", Result);
      Util.Files.Write_File (Path    => Path2,
                             Content => Result);

      Util.Tests.Assert_Equal_Files (T, "LICENSE.txt", Path2, "set/get big file failed");

   end Test_Tool_Set_Big;

   --  ------------------------------
   --  Test the akt get command.
   --  ------------------------------
   procedure Test_Tool_Get (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path ("regtests/files/test-keystore.akt");
      Output : constant String := Util.Tests.Get_Path ("regtests/result/test-get.txt");
      Expect : constant String := Util.Tests.Get_Test_Path ("regtests/expect/test-stream.txt");
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " -f " & Path
                 & " -p mypassword get -n list-1 list-2 list-3 list-4 LICENSE.txt "
                 & "> " & Output, Result, 0);
      Util.Tests.Assert_Equals (T, "", Result, "get -n command failed");
      Util.Tests.Assert_Equal_Files (T, Expect, Output,
                                     "akt get command returned invalid content");
   end Test_Tool_Get;

   --  ------------------------------
   --  Test the akt command with invalid parameters.
   --  ------------------------------
   procedure Test_Tool_Invalid (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path ("regtests/result/test-tool.akt");
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " -f " & Path & " -p admin unkown-cmd", Result, 1);
      Util.Tests.Assert_Matches (T, "^ERROR: Unkown command 'unkown-cmd'",
                                 Result, "Wrong message when command was not found");

      T.Execute (Tool & " -f " & Path & " -p admin -k create", Result, 1);
      Util.Tests.Assert_Matches (T, "^akt: unrecognized option '-k'",
                                 Result, "Wrong message for invalid option");

      --  Create keystore with a missing key file.
      T.Execute (Tool & " -f " & Path & " --passfile regtests/missing.key create",
                 Result, 1);
      Util.Tests.Assert_Matches (T, "^ERROR: Invalid password to unlock the keystore file",
                                 Result, "Wrong message when command was not found");

      --  Create keystore with a key file that does not satisfy the security constraints.
      T.Execute (Tool & " -f " & Path & " --passfile src/keystore.ads create",
                 Result, 1);
      Util.Tests.Assert_Matches (T, "^ERROR: Invalid password to unlock the keystore file",
                                 Result, "Wrong message when command was not found");

   end Test_Tool_Invalid;

   --  ------------------------------
   --  Test the akt edit command.
   --  ------------------------------
   procedure Test_Tool_Edit (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path ("regtests/result/test-tool.akt");
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " -f " & Path & " -p admin edit -e bad-command testing", Result, 1);

      T.Execute (Tool & " -f " & Path & " -p admin edit -e ./regtests/files/fake-editor edit",
                 Result, 0);

      T.Execute (Tool & " -f " & Path & " -p admin get edit", Result, 0);
      Util.Tests.Assert_Matches (T, "fake editor .*VALUE.txt.*", Result,
                                 "Invalid value after edit");

   end Test_Tool_Edit;

end Keystore.Tests;
