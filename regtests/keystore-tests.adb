-----------------------------------------------------------------------
--  keystore-tests -- Tests for akt command
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
with Ada.Streams.Stream_IO;
with Ada.Environment_Variables;
with GNAT.Regpat;
with Util.Files;
with Util.Test_Caller;
with Util.Encoders.AES;
with Util.Log.Loggers;
with Util.Processes;
with Util.Streams.Buffered;
with Util.Streams.Pipes;
with Util.Streams.Texts;
with Util.Streams.Files;
package body Keystore.Tests is

   use type Ada.Directories.File_Size;
   use type Ada.Streams.Stream_Element_Offset;
   use type Ada.Streams.Stream_Element_Array;

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Keystore.Tool");

   TEST_CONFIG_PATH : constant String := "regtests/result/test-config.properties";
   TEST_TOOL_PATH   : constant String := "regtests/result/test-tool.akt";
   TEST_TOOL2_PATH  : constant String := "regtests/result/test-tool-2.akt";
   TEST_TOOL3_PATH  : constant String := "regtests/result/test-tool-3.akt";
   DATA_TOOL3_PATH  : constant String := "regtests/result/test-tool-3";
   TEST_TOOL4_PATH  : constant String := "regtests/result/test-tool-4.akt";

   function Tool return String;
   function Compare (Path1 : in String;
                     Path2 : in String) return Boolean;

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
   procedure Test_Tool_Help_Set_Password is new Test_Help_Command ("password-set");
   procedure Test_Tool_Help_Add_Password is new Test_Help_Command ("password-add");
   procedure Test_Tool_Help_Remove_Password is new Test_Help_Command ("password-remove");
   procedure Test_Tool_Help_Store is new Test_Help_Command ("store");
   procedure Test_Tool_Help_Extract is new Test_Help_Command ("extract");
   procedure Test_Tool_Help_Config is new Test_Help_Command ("config");
   procedure Test_Tool_Help_Info is new Test_Help_Command ("info");

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
      Caller.Add_Test (Suite, "Test AKT.Commands.Set+Remove",
                       Test_Tool_Set_Remove_2'Access);
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
      Caller.Add_Test (Suite, "Test AKT.Commands.Info (help)",
                       Test_Tool_Help_Info'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.List (help)",
                       Test_Tool_Help_List'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Password.Add (help)",
                       Test_Tool_Help_Add_Password'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Password.Set (help)",
                       Test_Tool_Help_Set_Password'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Password.Remove (help)",
                       Test_Tool_Help_Remove_Password'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Store (help)",
                       Test_Tool_Help_Store'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Extract (help)",
                             Test_Tool_Help_Extract'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Config (help)",
                       Test_Tool_Help_Config'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Edit",
                       Test_Tool_Edit'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Store+Extract",
                       Test_Tool_Store_Extract'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Store+Extract (Dir tree)",
                       Test_Tool_Store_Extract_Tree'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Store (Error)",
                       Test_Tool_Store_Error'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Get (error)",
                       Test_Tool_Get_Error'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Get (interactive password)",
                       Test_Tool_Interactive_Password'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Password",
                       Test_Tool_Password_Set'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Create (separate data)",
                       Test_Tool_Separate_Data'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Config",
                       Test_Tool_Set_Config'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Extract (Error)",
                       Test_Tool_Extract_Error'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Info",
                       Test_Tool_Info'Access);
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

   function Compare (Path1 : in String;
                     Path2 : in String) return Boolean is
      In1   : Util.Streams.Files.File_Stream;
      In2   : Util.Streams.Files.File_Stream;
      Buf1  : Ada.Streams.Stream_Element_Array (1 .. 8192);
      Buf2  : Ada.Streams.Stream_Element_Array (1 .. 8192);
      Last1 : Ada.Streams.Stream_Element_Offset;
      Last2 : Ada.Streams.Stream_Element_Offset;
   begin
      In1.Open (Ada.Streams.Stream_IO.In_File, Path1);
      In2.Open (Ada.Streams.Stream_IO.In_File, Path2);
      loop
         In1.Read (Buf1, Last1);
         In2.Read (Buf2, Last2);
         if Last1 /= Last2 then
            return False;
         end if;
         exit when Last1 < Buf1'First;
         if Buf1 (Buf1'First .. Last1) /= Buf2 (Buf2'First .. Last2) then
            return False;
         end if;
      end loop;
      return True;

   exception
      when others =>
         return False;
   end Compare;

   procedure Store_Extract (T       : in out Test;
                            Command : in String;
                            Name    : in String;
                            Path    : in String) is
      Output_Path : constant String := Util.Tests.Get_Test_Path ("regtests/result/" & Name);
      Result      : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " store " & Command & " -- " & Name & " < " & Path, Result);

      T.Execute (Tool & " extract " & Command & " -- " & Name & " > " & Output_Path, Result);

      T.Assert (Compare (Path, Output_Path),
                "store+extract invalid for " & Name);
   end Store_Extract;

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
      Path   : constant String := Util.Tests.Get_Test_Path (TEST_TOOL_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      if Ada.Directories.Exists (Path) then
         Ada.Directories.Delete_File (Path);
      end if;

      --  Create keystore
      T.Execute (Tool & " create " & Path & " -p admin --counter-range 10:100", Result);
      Util.Tests.Assert_Equals (T, "", Result, "create command failed");
      T.Assert (Ada.Directories.Exists (Path),
                "Keystore file does not exist");

      --  List content => empty result
      T.Execute (Tool & " list " & Path & " -p admin", Result);
      Util.Tests.Assert_Equals (T, "", Result, "list command failed");

      --  Set property
      T.Execute (Tool & " set " & Path & " -p admin testing my-testing-value", Result);
      Util.Tests.Assert_Equals (T, "", Result, "set command failed");

      --  Get property
      T.Execute (Tool & " get " & Path & " -p admin testing", Result);
      Util.Tests.Assert_Matches (T, "^my-testing-value", Result, "get command failed");

      --  List content => one entry
      T.Execute (Tool & " list " & Path & " -p admin", Result);
      Util.Tests.Assert_Matches (T, "^testing", Result, "list command failed");

      --  Open keystore with invalid password
      T.Execute (Tool & " list " & Path & " -p admin2", Result, 1);
      Util.Tests.Assert_Matches (T, "^Invalid password to unlock the keystore file",
                                 Result, "list command failed");

   end Test_Tool_Create;

   --  ------------------------------
   --  Test the akt keystore creation with password file.
   --  ------------------------------
   procedure Test_Tool_Create_Password_File (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path (TEST_TOOL_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      if Ada.Directories.Exists (Path) then
         Ada.Directories.Delete_File (Path);
      end if;

      --  Create keystore
      --  file.key must have rw------- mode (600)
      --  regtests/files must have rwx------ (700)
      T.Execute (Tool & " create -k " & Path & " --passfile regtests/files/file.key "
                 & "--counter-range 100:200",
                 Result, 0);
      Util.Tests.Assert_Equals (T, "", Result, "create command failed");
      T.Assert (Ada.Directories.Exists (Path),
                "Keystore file does not exist");

      --  Set property
      T.Execute (Tool & " set -k " & Path & " --passfile regtests/files/file.key "
                 & "testing my-testing-value", Result);
      Util.Tests.Assert_Equals (T, "", Result, "set command failed");

      --  List content => one entry
      T.Execute (Tool & " list -k " & Path & " --passfile regtests/files/file.key", Result);
      Util.Tests.Assert_Matches (T, "^testing", Result, "list command failed");

   end Test_Tool_Create_Password_File;

   --  ------------------------------
   --  Test the akt command adding and removing values.
   --  ------------------------------
   procedure Test_Tool_Set_Remove (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path (TEST_TOOL_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      Test_Tool_Create (T);

      --  Set property
      T.Execute (Tool & " set -k " & Path & " -p admin "
                 & "testing my-new-testing-value", Result);
      Util.Tests.Assert_Equals (T, "", Result, "set command failed");

      --  Remove property
      T.Execute (Tool & " remove " & Path & " -p admin "
                 & "testing", Result);
      Util.Tests.Assert_Equals (T, "", Result, "remove command failed");

      T.Execute (Tool & " remove " & Path & " -p admin", Result, 1);

   end Test_Tool_Set_Remove;

   --  ------------------------------
   --  Test the akt command adding and removing values.
   --  ------------------------------
   procedure Test_Tool_Set_Remove_2 (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path (TEST_TOOL2_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
      Size   : Ada.Directories.File_Size;
   begin
      if Ada.Directories.Exists (Path) then
         Ada.Directories.Delete_File (Path);
      end if;

      --  Create keystore
      T.Execute (Tool & " create -k " & Path & " -p admin --counter-range 10:100", Result);
      Util.Tests.Assert_Equals (T, "", Result, "create command failed");
      T.Assert (Ada.Directories.Exists (Path),
                "Keystore file does not exist");

      --  Set property with configure file (128K file or more).
      T.Execute (Tool & " store -k " & Path & " -p admin "
                 & "configure", Result);
      Util.Tests.Assert_Equals (T, "", Result, "set command failed");

      Size := Ada.Directories.Size (Path);
      T.Assert (Size > 100_000, "Keystore file looks too small");

      --  Remove property.
      T.Execute (Tool & " remove -k " & Path & " -p admin "
                 & "configure", Result);
      Util.Tests.Assert_Equals (T, "", Result, "remove command failed");

      Size := Ada.Directories.Size (Path);
      T.Assert (Size < 13_000, "Keystore file was not truncated after removal of large content");

      T.Execute (Tool & " remove -k " & Path & " -p admin", Result, 1);

   end Test_Tool_Set_Remove_2;

   --  ------------------------------
   --  Test the akt command setting a big file.
   --  ------------------------------
   procedure Test_Tool_Set_Big (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path (TEST_TOOL_PATH);
      Path2  : constant String := Util.Tests.Get_Test_Path ("regtests/result/big-content.txt");
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      Test_Tool_Create (T);

      --  Set property
      T.Execute (Tool & " store " & Path & " -p admin "
                 & "LICENSE.txt", Result);
      Util.Tests.Assert_Equals (T, "", Result, "store <file> command failed");

      --  Get the property
      T.Execute (Tool & " get -k " & Path & " -p admin LICENSE.txt", Result);
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
      T.Execute (Tool & " get -k " & Path
                 & " -p mypassword -n list-1 list-2 list-3 list-4 LICENSE.txt "
                 & "> " & Output, Result, 0);
      Util.Tests.Assert_Equals (T, "", Result, "get -n command failed");
      Util.Tests.Assert_Equal_Files (T, Expect, Output,
                                     "akt get command returned invalid content");
   end Test_Tool_Get;

   --  ------------------------------
   --  Test the akt get command with errors.
   --  ------------------------------
   procedure Test_Tool_Get_Error (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path ("regtests/files/test-keystore.akt");
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " get -k " & Path
                 & " -p mypassword", Result, 1);
      T.Execute (Tool & " get -k " & Path
                 & " -p mypassword missing-property", Result, 1);
   end Test_Tool_Get_Error;

   --  ------------------------------
   --  Test the akt command with invalid parameters.
   --  ------------------------------
   procedure Test_Tool_Invalid (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path (TEST_TOOL_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " unkown-cmd -k " & Path & " -p admin", Result, 1);
      Util.Tests.Assert_Matches (T, "^Unkown command 'unkown-cmd'",
                                 Result, "Wrong message when command was not found");

      T.Execute (Tool & " create -k " & Path & " -p admin -q", Result, 1);
      Util.Tests.Assert_Matches (T, "^akt: unrecognized option '-q'",
                                 Result, "Wrong message for invalid option");

      --  Create keystore with a missing key file.
      T.Execute (Tool & " create -k " & Path & " --force --passfile regtests/missing.key",
                 Result, 1);
      Util.Tests.Assert_Matches (T, "^Invalid password to unlock the keystore file",
                                 Result, "Wrong message when command was not found");

      --  Create keystore with a key file that does not satisfy the security constraints.
      T.Execute (Tool & " create -k " & Path & " --passfile src/keystore.ads",
                 Result, 1);
      Util.Tests.Assert_Matches (T, "^Invalid password to unlock the keystore file",
                                 Result, "Wrong message when command was not found");

      T.Execute (Tool & " set -k " & Path & " -p admin", Result, 1);

      T.Execute (Tool & " set -k " & Path & " -p admin a b c", Result, 1);

      T.Execute (Tool & " set -k " & Path & " -p admin -f test", Result, 1);

      T.Execute (Tool & " set -k " & Path & " -p admin -f test c d", Result, 1);

      T.Execute (Tool & " set -k " & Path & " -p admin", Result, 1);

      T.Execute (Tool & " -k " & Path & " -p admin", Result, 1);

      T.Execute (Tool & " -vv get -k " & Path & " -p admin testing", Result, 0);

      T.Execute (Tool & " -v get -k " & Path & " -p admin testing", Result, 0);

      T.Execute (Tool & " get -k x" & Path & " -p admin testing", Result, 1);

   end Test_Tool_Invalid;

   --  ------------------------------
   --  Test the akt edit command.
   --  ------------------------------
   procedure Test_Tool_Edit (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path (TEST_TOOL_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " edit -k " & Path & " -p admin -e bad-command testing", Result, 1);

      T.Execute (Tool & " edit -k " & Path & " -p admin -e ./regtests/files/fake-editor edit",
                 Result, 0);

      T.Execute (Tool & " get -k " & Path & " -p admin edit", Result, 0);
      Util.Tests.Assert_Matches (T, "fake editor .*VALUE.txt.*", Result,
                                 "Invalid value after edit");

      --  Setup EDITOR environment variable.
      Ada.Environment_Variables.Set ("EDITOR", "./regtests/files/fake-editor");

      T.Execute (Tool & " edit -k " & Path & " -p admin edit-env-test",
                 Result, 0);

      T.Execute (Tool & " get -k " & Path & " -p admin edit-env-test", Result, 0);
      Util.Tests.Assert_Matches (T, "fake editor .*VALUE.txt.*", Result,
                                 "Invalid value after edit");

   end Test_Tool_Edit;

   --  ------------------------------
   --  Test the akt store and akt extract commands.
   --  ------------------------------
   procedure Test_Tool_Store_Extract (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path (TEST_TOOL_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " create -k " & Path & " -p admin -c 1:10 --force", Result, 0);
      T.Execute (Tool & " store -k " & Path & " -p admin -- store-extract < bin/akt", Result, 0);
      T.Execute (Tool & " extract -k " & Path & " -p admin -- store-extract > regtests/result/akt",
                 Result, 0);

      --  Check extract command with invalid value
      T.Execute (Tool & " extract -k " & Path & " -p admin missing",
                 Result, 1);
      Util.Tests.Assert_Matches (T, "^Value 'missing' not found", Result,
                                 "Invalid value for extract command");

      --  Check extract command with missing parameter
      T.Execute (Tool & " extract -k " & Path & " -p admin",
                 Result, 1);
      Util.Tests.Assert_Matches (T, "Missing file or directory to extract", Result,
                                 "Expecting usage print for extract command");
   end Test_Tool_Store_Extract;

   --  ------------------------------
   --  Test the akt store and akt extract commands.
   --  ------------------------------
   procedure Test_Tool_Store_Extract_Tree (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path (TEST_TOOL_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " create " & Path & " -p admin -c 1:10 --force", Result, 0);
      T.Execute (Tool & " store " & Path & " -p admin obj bin", Result, 0);
      T.Execute (Tool & " extract " & Path & " -p admin -o regtests/result/extract bin",
                 Result, 0);

      T.Assert (Compare ("bin/akt", "regtests/result/extract/bin/akt"),
                "store+extract failed for bin/akt");

      T.Assert (Compare ("bin/keystore_harness", "regtests/result/extract/bin/keystore_harness"),
                "store+extract failed for bin/keystore_harness");

      T.Execute (Tool & " extract " & Path & " -p admin -o regtests/result/extract-obj obj",
                 Result, 0);

      T.Assert (Compare ("obj/akt.o", "regtests/result/extract-obj/obj/akt.o"),
                "store+extract failed for obj/akt.o");

      T.Assert (Compare ("obj/akt-commands.o", "regtests/result/extract-obj/obj/akt-commands.o"),
                "store+extract failed for obj/akt-commands.o");

   end Test_Tool_Store_Extract_Tree;

   --  ------------------------------
   --  Test the akt store command with errors.
   --  ------------------------------
   procedure Test_Tool_Store_Error (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path (TEST_TOOL_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " create " & Path & " -p admin -c 1:10 --force", Result, 0);

      T.Execute (Tool & " store " & Path & " -p admin --", Result, 1);

      T.Execute (Tool & " store " & Path & " -p admin this-file-does-not-exist", Result, 1);

      T.Execute (Tool & " store " & Path & " -p admin /dev/null", Result, 1);
   end Test_Tool_Store_Error;

   procedure Test_Tool_Extract_Error (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path (TEST_TOOL4_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " create " & Path & " -p admin -c 1:10 --force", Result, 0);

      T.Execute (Tool & " extract " & Path & " -p admin missing-1", Result, 1);
      Util.Tests.Assert_Matches (T, "^Value 'missing-1' not found", Result,
                                 "Invalid value for extract command");

      T.Execute (Tool & " extract " & Path & " -p admin -- missing-2", Result, 1);
      Util.Tests.Assert_Matches (T, "^Value 'missing-2' not found", Result,
                                 "Invalid value for extract command");
   end Test_Tool_Extract_Error;


   --  ------------------------------
   --  Test the akt password-set command.
   --  ------------------------------
   procedure Test_Tool_Password_Set (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path (TEST_TOOL_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " password-set -k " & Path & " -p admin --new-password admin-second "
                 & " --counter-range 10:100",
                 Result, 0);
      Util.Tests.Assert_Equals (T, "", Result,
                                "Bad output for password-set command");

      --  Check using old password.
      T.Execute (Tool & " password-set -k " & Path & " -p admin --new-password admin-ko",
                 Result, 1);
      Util.Tests.Assert_Matches (T, "^Invalid password to unlock the keystore file",
                                 Result, "password-set command failed");

      --  Add new password
      T.Execute (Tool & " password-add -k " & Path & " -p admin-second --new-password admin "
                 & " --counter-range 10:100",
                 Result, 0);
      Util.Tests.Assert_Equals (T, "", Result,
                                "Bad output for password-set command");

      --  Remove added password
      T.Execute (Tool & " password-remove -k " & Path & " -p admin-second --slot 2",
                 Result, 0);

      Util.Tests.Assert_Matches (T, "^The password was successfully removed.", Result,
                                 "Bad output for password-remove command");

   end Test_Tool_Password_Set;

   --  ------------------------------
   --  Test the akt with an interactive password.
   --  ------------------------------
   procedure Test_Tool_Interactive_Password (T : in out Test) is
      Path     : constant String := Util.Tests.Get_Test_Path (TEST_TOOL_PATH);
      P        : aliased Util.Streams.Pipes.Pipe_Stream;
      Buffer   : Util.Streams.Texts.Print_Stream;
   begin
      P.Open (Tool & " list -k " & Path, Util.Processes.WRITE);
      Buffer.Initialize (P'Unchecked_Access, 8192);
      Buffer.Write ("admin");
      Buffer.Flush;
      P.Close;
      Util.Tests.Assert_Equals (T, 0, P.Get_Exit_Status,
                                "Failed to pass the password as interactive");

      P.Open (Tool & " list -k " & Path, Util.Processes.WRITE);
      Buffer.Write ("invalid");
      Buffer.Flush;
      P.Close;
      Util.Tests.Assert_Equals (T, 1, P.Get_Exit_Status,
                                "Failed to pass the password as interactive");

   end Test_Tool_Interactive_Password;

   --  ------------------------------
   --  Test the akt with data blocks written in separate files.
   --  ------------------------------
   procedure Test_Tool_Separate_Data (T : in out Test) is
      Path     : constant String := Util.Tests.Get_Test_Path (TEST_TOOL3_PATH);
      Data     : constant String := Util.Tests.Get_Test_Path (DATA_TOOL3_PATH);
      P        : aliased Util.Streams.Pipes.Pipe_Stream;
      Buffer   : Util.Streams.Texts.Print_Stream;
   begin
      if not Ada.Directories.Exists (Data) then
         Ada.Directories.Create_Path (Data);
      end if;
      P.Open (Tool & " create -k " & Path & " -d " & Data & " -c 10:20 --force",
              Util.Processes.WRITE);
      Buffer.Initialize (P'Unchecked_Access, 8192);
      Buffer.Write ("admin");
      Buffer.Flush;
      P.Close;
      Util.Tests.Assert_Equals (T, 0, P.Get_Exit_Status,
                                "Failed to pass the password as interactive");

      T.Store_Extract (" -k " & Path & " -d " & Data & " -p admin ",
                       "data-makefile", "Makefile");

      T.Store_Extract (" -k " & Path & " -d " & Data & " -p admin ",
                       "data-configure", "configure");

      T.Store_Extract (" -k " & Path & " -d " & Data & " -p admin ",
                       "data-license.txt", "LICENSE.txt");

      T.Store_Extract (" -k " & Path & " -d " & Data & " -p admin ",
                       "data-bin-akt", "bin/akt");

   end Test_Tool_Separate_Data;

   --  ------------------------------
   --  Test the akt config command.
   --  ------------------------------
   procedure Test_Tool_Set_Config (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path (TEST_CONFIG_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      if Ada.Directories.Exists (Path) then
         Ada.Directories.Delete_File (Path);
      end if;

      T.Execute (Tool & " --config " & Path & " config fill-zero no",
                 Result, 0);
      Util.Tests.Assert_Equals (T, "", Result,
                                "Bad output for config command");
      T.Assert (Ada.Directories.Exists (Path),
                "Config file '" & Path & "' does not exist after test");

   end Test_Tool_Set_Config;

   --  ------------------------------
   --  Test the akt info command on several keystore files.
   --  ------------------------------
   procedure Test_Tool_Info (T : in out Test) is
      function Extract_UUID (Content : in String) return String;

      Path    : constant String := Util.Tests.Get_Test_Path (TEST_TOOL3_PATH);
      Dir     : constant String := Util.Tests.Get_Test_Path (DATA_TOOL3_PATH);

      function Extract_UUID (Content : in String) return String is
         REGEX   : constant String := ".*UUID +([0-9A-F-]*).*";
         Pattern : constant GNAT.Regpat.Pattern_Matcher := GNAT.Regpat.Compile (REGEX);
         Matches : GNAT.Regpat.Match_Array (0 .. 1);
      begin
         T.Assert (GNAT.Regpat.Match (Pattern, Content),
                   "akt info output does not match UUID pattern");
         GNAT.Regpat.Match (Pattern, Content, Matches);
         return Content (Matches (1).First .. Matches (1).Last);
      end Extract_UUID;

      Result  : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " info " & Path & " -p admin", Result, 0);

      declare
         Id : constant String := Extract_UUID (Ada.Strings.Unbounded.To_String (Result));
      begin
         T.Execute (Tool & " info " & Dir & "/" & Id & "-1.dkt -p admin", Result, 0);
      end;
   end Test_Tool_Info;

end Keystore.Tests;
