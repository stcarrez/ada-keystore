-----------------------------------------------------------------------
--  keystore-tests -- Tests for akt command
--  Copyright (C) 2019, 2020, 2021, 2022, 2023 Stephane Carrez
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
with Util.Strings;
with Util.Test_Caller;
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

   TEST_CONFIG_PATH : constant String := "test-config.properties";
   TEST_TOOL_PATH   : constant String := "test-tool.akt";
   TEST_TOOL2_PATH  : constant String := "test-tool-2.akt";
   TEST_TOOL3_PATH  : constant String := "test-tool-3.akt";
   DATA_TOOL3_PATH  : constant String := "test-tool-3";
   TEST_TOOL4_PATH  : constant String := "test-tool-4.akt";
   TEST_TOOL5_PATH  : constant String := "test-tool-5.akt";
   TEST_TOOL6_PATH  : constant String := "test-tool-6.akt";
   TEST_TOOL7_PATH  : constant String := "test-tool-7.akt";
   TEST_WALLET_KEY_PATH  : constant String := "keys/wallet.keys";
   TEST_CORRUPTED_1_PATH : constant String := "regtests/files/test-corrupted-1.akt";
   TEST_CORRUPTED_2_PATH : constant String := "regtests/files/test-corrupted-2.akt";
   TEST_WALLET_PATH      : constant String := "regtests/files/test-wallet.akt";
   TEST_SPLIT_PATH       : constant String := "regtests/files/test-split.akt";
   TEST_OTP_PATH         : constant String := "regtests/files/test-otp.akt";

   function Tool return String;
   function Compare (Path1 : in String;
                     Path2 : in String) return Boolean;

   package Caller is new Util.Test_Caller (Test, "AKT.Tools");

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
      if not Is_Windows then
         Caller.Add_Test (Suite, "Test AKT.Commands.Create (password-cmd)",
                          Test_Tool_Create_Password_Command'Access);
      end if;
      Caller.Add_Test (Suite, "Test AKT.Commands.Create (Error)",
                       Test_Tool_Create_Error'Access);
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
      if not Is_Windows then
         --  The test must be adapted for Windows.
         Caller.Add_Test (Suite, "Test AKT.Commands.Edit",
                          Test_Tool_Edit'Access);
         Caller.Add_Test (Suite, "Test AKT.Commands.Edit (Error)",
                          Test_Tool_Edit_Error'Access);
      end if;
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
      Caller.Add_Test (Suite, "Test AKT.Commands.Info (Error)",
                       Test_Tool_Info_Error'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Create (Wallet_Key)",
                       Test_Tool_With_Wallet_Key_File'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Password (Slot limit)",
                       Test_Tool_Password_Add_Limit'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.List (No file provided)",
                       Test_Tool_List_Error'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Open (Corrupted)",
                       Test_Tool_Corrupted_1'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Open (Corrupted data)",
                       Test_Tool_Corrupted_2'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Open (Missing Storage)",
                       Test_Tool_Missing_Storage'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands (-V)",
                       Test_Tool_Version'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands (Invalid file)",
                       Test_Tool_Bad_File'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.List (Nested wallet)",
                       Test_Tool_Nested_Wallet'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.OTP",
                       Test_Tool_OTP'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.OTP (Errors)",
                       Test_Tool_OTP_Error'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Genkey",
                       Test_Tool_Genkey'Access);
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
                      Input   : in String;
                      Output  : in String;
                      Result  : out Ada.Strings.Unbounded.Unbounded_String;
                      Status  : in Natural := 0) is
      P        : aliased Util.Streams.Pipes.Pipe_Stream;
      Buffer   : Util.Streams.Buffered.Input_Buffer_Stream;
   begin
      if Input'Length > 0 then
         Log.Info ("Execute: {0} < {1}", Command, Input);
      elsif Output'Length > 0 then
         Log.Info ("Execute: {0} > {1}", Command, Output);
      else
         Log.Info ("Execute: {0}", Command);
      end if;
      P.Set_Input_Stream (Input);
      P.Set_Output_Stream (Output);
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
                      Result  : out Ada.Strings.Unbounded.Unbounded_String;
                      Status  : in Natural := 0) is
   begin
      T.Execute (Command, "", "", Result, Status);
   end Execute;

   procedure Execute (T       : in out Test;
                      Command : in String;
                      Expect  : in String;
                      Status  : in Natural := 0) is
      Path   : constant String := Util.Tests.Get_Path ("regtests/expect/" & Expect);
      Output : constant String := Util.Tests.Get_Test_Path (Expect);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Command, "", Output, Result, Status);

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
      Output_Path : constant String := Util.Tests.Get_Test_Path (Name);
      Result      : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " store " & Command & " -- " & Name, Path, "", Result);

      T.Execute (Tool & " extract " & Command & " -- " & Name, "", Output_Path, Result);

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
      Util.Tests.Assert_Matches (T, "^akt: invalid password to unlock the keystore file",
                                 Result, "list command failed");

   end Test_Tool_Create;

   --  ------------------------------
   --  Test the akt keystore creation.
   --  ------------------------------
   procedure Test_Tool_Create_Error (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path (TEST_TOOL_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      --  Wrong option --counter-range
      T.Execute (Tool & " create " & Path & " -p admin --counter-range bob", Result, 1);
      Util.Tests.Assert_Matches (T, "akt: invalid counter range: bob", Result,
                                 "Invalid message");

      --  Missing parameter for -c option
      T.Execute (Tool & " create " & Path & " -p admin -c", Result, 1);
      Util.Tests.Assert_Matches (T, "akt: missing option parameter", Result,
                                 "Invalid message");

      --  Wrong range
      T.Execute (Tool & " create " & Path & " -p admin --counter-range 100:1", Result, 1);
      Util.Tests.Assert_Matches (T, "akt: the min counter is greater than max counter", Result,
                                 "Invalid message");

      T.Execute (Tool & " create " & Path & " -p admin --counter-range 100000000000", Result, 1);
      Util.Tests.Assert_Matches (T, "akt: invalid counter range: 100000000000", Result,
                                 "Invalid message");

      T.Execute (Tool & " create " & Path & " -p admin --counter-range -1000", Result, 1);
      Util.Tests.Assert_Matches (T, "akt: value is out of range", Result,
                                 "Invalid message");

   end Test_Tool_Create_Error;

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
   --  Test the akt keystore creation with password file.
   --  ------------------------------
   procedure Test_Tool_Create_Password_Command (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path (TEST_TOOL_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      if Ada.Directories.Exists (Path) then
         Ada.Directories.Delete_File (Path);
      end if;

      T.Execute (Tool & " create -k " & Path & " --passcmd 'echo -n admin' "
                 & "--counter-range 100:200",
                 Result, 0);
      Util.Tests.Assert_Equals (T, "", Result, "create command failed");
      T.Assert (Ada.Directories.Exists (Path),
                "Keystore file does not exist");

      --  Set property
      T.Execute (Tool & " set -k " & Path & " --passcmd 'echo -n admin' "
                 & "testing my-testing-value", Result);
      Util.Tests.Assert_Equals (T, "", Result, "set command failed");

      --  List content => one entry
      T.Execute (Tool & " list -k " & Path & " --passcmd 'echo -n admin'", Result);
      Util.Tests.Assert_Matches (T, "^testing", Result, "list command failed");

      --  Try using an invalid command
      T.Execute (Tool & " list -k " & Path & " --passcmd 'missing-command'", Result, 1);
      Util.Tests.Assert_Matches (T, "akt: invalid password to unlock the keystore file",
                                 Result, "no error reported");

      --  Try using a command that produces an empty password
      T.Execute (Tool & " list -k " & Path & " --passcmd true", Result, 1);
      Util.Tests.Assert_Matches (T, "akt: invalid password to unlock the keystore file",
                                 Result, "no error reported");

   end Test_Tool_Create_Password_Command;

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
      Path2  : constant String := Util.Tests.Get_Test_Path ("big-content.txt");
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
      Path   : constant String := Util.Tests.Get_Path ("regtests/files/test-keystore.akt");
      Output : constant String := Util.Tests.Get_Test_Path ("test-get.txt");
      Expect : constant String := Util.Tests.Get_Path ("regtests/expect/test-stream.txt");
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " get -k " & Path
                 & " -p mypassword -n list-1 list-2 list-3 list-4 LICENSE.txt ",
                 "", Output, Result, 0);
      Util.Tests.Assert_Equals (T, "", Result, "get -n command failed");
      Util.Tests.Assert_Equal_Files (T, Expect, Output,
                                     "akt get command returned invalid content");
   end Test_Tool_Get;

   --  ------------------------------
   --  Test the akt get command with errors.
   --  ------------------------------
   procedure Test_Tool_Get_Error (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Path ("regtests/files/test-keystore.akt");
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " get -k " & Path
                 & " -p mypassword", Result, 1);
      T.Execute (Tool & " get -k " & Path
                 & " -p mypassword missing-property", Result, 1);
      Util.Tests.Assert_Matches (T, "^akt: value 'missing-property' not found",
                                 Result, "Invalid error message when value was not found");

   end Test_Tool_Get_Error;

   --  ------------------------------
   --  Test the akt command with invalid parameters.
   --  ------------------------------
   procedure Test_Tool_Invalid (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path (TEST_TOOL_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " unkown-cmd -k " & Path & " -p admin", Result, 1);
      Util.Tests.Assert_Matches (T, "^akt: unknown command 'unkown-cmd'",
                                 Result, "Wrong message when command was not found");

      T.Execute (Tool & " create -k " & Path & " -p admin -q", Result, 1);
      Util.Tests.Assert_Matches (T, "^akt" & EXE & ": unrecognized option '-q'",
                                 Result, "Wrong message for invalid option");

      --  Create keystore with a missing key file.
      T.Execute (Tool & " create -k " & Path & " --force --passfile regtests/missing.key",
                 Result, 1);
      Util.Tests.Assert_Matches (T, "^akt: invalid password to unlock the keystore file",
                                 Result, "Wrong message when command was not found");

      --  Create keystore with a key file that does not satisfy the security constraints.
      T.Execute (Tool & " create -k " & Path & " --passfile src/keystore.ads",
                 Result, 1);
      Util.Tests.Assert_Matches (T, "^akt: invalid password to unlock the keystore file",
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
   --  Test the akt edit command.
   --  ------------------------------
   procedure Test_Tool_Edit_Error (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path (TEST_TOOL_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " edit -k " & Path & " -p admin -e bad-command testing", Result, 1);
      Util.Tests.Assert_Matches (T, ".*akt: editor exited with status 127", Result,
                                 "Invalid value after edit");

      T.Execute (Tool & " edit -k " & Path & " -p admin -e ./regtests/files/error-editor edit",
                 Result, 1);
      Util.Tests.Assert_Matches (T, "^akt: editor exited with status 23", Result,
                                 "Invalid value after edit");

      T.Execute (Tool & " edit -k " & Path & " -p admin -e ./regtests/files/error2-editor edit",
                 Result, 1);
      Util.Tests.Assert_Matches (T, "^akt: cannot read the editor's output", Result,
                                 "Invalid value after edit");
   end Test_Tool_Edit_Error;

   --  ------------------------------
   --  Test the akt store and akt extract commands.
   --  ------------------------------
   procedure Test_Tool_Store_Extract (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path (TEST_TOOL_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " create -k " & Path & " -p admin -c 1:10 --force", Result, 0);
      T.Execute (Tool & " store -k " & Path & " -p admin -- store-extract",
                 "bin/akt" & EXE, "",
                 Result, 0);
      T.Execute (Tool & " extract -k " & Path & " -p admin -- store-extract",
                 "", Util.Tests.Get_Test_Path ("akt"),
                 Result, 0);

      --  Check extract command with invalid value
      T.Execute (Tool & " extract -k " & Path & " -p admin missing",
                 Result, 1);
      Util.Tests.Assert_Matches (T, "^akt: value 'missing' not found", Result,
                                 "Invalid value for extract command");

      --  Check extract command with missing parameter
      T.Execute (Tool & " extract -k " & Path & " -p admin",
                 Result, 1);
      Util.Tests.Assert_Matches (T, "akt: missing file or directory to extract", Result,
                                 "Expecting usage print for extract command");
   end Test_Tool_Store_Extract;

   --  ------------------------------
   --  Test the akt store and akt extract commands.
   --  ------------------------------
   procedure Test_Tool_Store_Extract_Tree (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path (TEST_TOOL_PATH);
      Dir    : constant String := Util.Tests.Get_Test_Path ("extract");
      Obj    : constant String := Util.Tests.Get_Test_Path ("extract-obj");
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " create " & Path & " -p admin -c 1:10 --force", Result, 0);
      T.Execute (Tool & " store " & Path & " -p admin obj bin", Result, 0);
      T.Execute (Tool & " extract " & Path & " -p admin -o " & Dir & " bin",
                 Result, 0);

      T.Assert (Compare ("bin/akt" & EXE, Dir & "/bin/akt" & EXE),
                "store+extract failed for bin/akt");

      T.Assert (Compare ("bin/keystore_harness" & EXE,
                Dir & "/bin/keystore_harness" & EXE),
                "store+extract failed for bin/keystore_harness");

      T.Execute (Tool & " extract " & Path & " -p admin -o " & Obj & " obj",
                 Result, 0);

      T.Assert (Compare ("obj/akt.o", Obj & "/obj/akt.o"),
                "store+extract failed for obj/akt.o");

      T.Assert (Compare ("obj/akt-commands.o", Obj & "/obj/akt-commands.o"),
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
      Util.Tests.Assert_Matches (T, "^akt: value 'missing-1' not found", Result,
                                 "Invalid value for extract command");

      T.Execute (Tool & " extract " & Path & " -p admin -- missing-2", Result, 1);
      Util.Tests.Assert_Matches (T, "^akt: value 'missing-2' not found", Result,
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
      Util.Tests.Assert_Matches (T, "^akt: invalid password to unlock the keystore file",
                                 Result, "password-set command failed");

      --  Add new password
      T.Execute (Tool & " password-add -k " & Path & " -p admin-second --new-password admin "
                 & " --counter-range 10:100",
                 Result, 0);
      Util.Tests.Assert_Equals (T, "", Result,
                                "Bad output for password-set command");

      --  Remove added password
      T.Execute (Tool & " password-remove -k " & Path & " -p admin-second -f",
                 Result, 0);

      Util.Tests.Assert_Matches (T, "^The password was successfully removed.", Result,
                                 "Bad output for password-remove command");

   end Test_Tool_Password_Set;

   --  ------------------------------
   --  Test the akt password-add command reaching the limit.
   --  ------------------------------
   procedure Test_Tool_Password_Add_Limit (T : in out Test) is
      Path   : constant String := Util.Tests.Get_Test_Path (TEST_TOOL_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      for I in 1 .. 6 loop
         T.Execute (Tool & " password-add " & Path & " -p admin --new-password "
                    & "admin-" & Util.Strings.Image (I) & " --counter-range 10:100",
                    Result, 0);
      end loop;

      T.Execute (Tool & " password-add " & Path & " -p admin --new-password "
                 & "admin-8 --counter-range 10:100",
                 Result, 1);

      Util.Tests.Assert_Matches (T, "^akt: there is no available key slot to add the password",
                                 Result,
                                 "Bad output for password-add command");
   end Test_Tool_Password_Add_Limit;

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
                       "data-bin-akt", "bin/akt" & EXE);

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

   procedure Test_Tool_Info_Error (T : in out Test) is
      Result  : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " info Makefile", Result, 1);
      T.Execute (Tool & " info some-missing-file", Result, 1);
   end Test_Tool_Info_Error;

   procedure Test_Tool_List_Error (T : in out Test) is
      Result  : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " list -p admin", Result, 1);
      Util.Tests.Assert_Matches (T, "^akt: missing the keystore file name",
                                 Result,
                                 "Bad output for list command");
   end Test_Tool_List_Error;

   --  ------------------------------
   --  Test the akt commands with --wallet-key-file
   --  ------------------------------
   procedure Test_Tool_With_Wallet_Key_File (T : in out Test) is
      Path    : constant String := Util.Tests.Get_Test_Path (TEST_TOOL5_PATH);
      Keys    : constant String := Util.Tests.Get_Test_Path (TEST_WALLET_KEY_PATH);
      Result  : Ada.Strings.Unbounded.Unbounded_String;
   begin
      if Ada.Directories.Exists (Path) then
         Ada.Directories.Delete_File (Path);
      end if;

      --  Create keystore
      T.Execute (Tool & " create " & Path & " --wallet-key-file " & Keys &
                   " -p admin --counter-range 10:100", Result);
      Util.Tests.Assert_Equals (T, "", Result, "create command failed");
      T.Assert (Ada.Directories.Exists (Path),
                "Keystore file does not exist");

      --  List content => empty result
      T.Execute (Tool & " list " & Path & " --wallet-key-file " & Keys & " -p admin", Result);
      Util.Tests.Assert_Equals (T, "", Result, "list command failed");

      --  Set property
      T.Execute (Tool & " set " & Path & " --wallet-key-file " & Keys &
                   " -p admin testing my-testing-value", Result);
      Util.Tests.Assert_Equals (T, "", Result, "set command failed");

      --  Even with good password, unlocking should fail because of missing wallet-key-file.
      T.Execute (Tool & " list " & Path & " -p admin testing my-testing-value", Result, 1);
      Util.Tests.Assert_Matches (T, "akt: invalid password to unlock the keystore file",
                                 Result, "list command failed");
   end Test_Tool_With_Wallet_Key_File;

   procedure Test_Tool_Corrupted_1 (T : in out Test) is
      Path    : constant String := Util.Tests.Get_Path (TEST_CORRUPTED_1_PATH);
      Result  : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " list " & Path & " -p mypassword", Result, 1);
      Util.Tests.Assert_Matches (T, "akt: the keystore file is corrupted: "
                                   & "invalid meta data content",
                                 Result, "list command failed");
   end Test_Tool_Corrupted_1;

   procedure Test_Tool_Corrupted_2 (T : in out Test) is
      Path    : constant String := Util.Tests.Get_Path (TEST_CORRUPTED_2_PATH);
      Result  : Ada.Strings.Unbounded.Unbounded_String;
   begin
      --  This keystore file was corrupted while implementing the Write procedure.
      --  The data HMAC is invalid but every block is correctly signed and encrypted.
      T.Execute (Tool & " get " & Path & " -p mypassword Update_Stream", Result, 1);
      Util.Tests.Assert_Matches (T, "akt: the keystore file is corrupted: "
                                   & "invalid meta data content",
                                 Result, "list command failed");
   end Test_Tool_Corrupted_2;

   procedure Test_Tool_Missing_Storage (T : in out Test) is
      Path    : constant String := Util.Tests.Get_Path (TEST_SPLIT_PATH);
      Result  : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " list " & Path & " -p admin", Result, 1);
      Util.Tests.Assert_Matches
        (T, "akt: the keystore file is corrupted: invalid or missing storage file",
         Result, "list command failed");
   end Test_Tool_Missing_Storage;

   procedure Test_Tool_Version (T : in out Test) is
      Result  : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " -V", Result, 0);
      Util.Tests.Assert_Matches (T, "Ada Keystore Tool 1.[0-9].[0-9]",
                                 Result, "akt -V option");
   end Test_Tool_Version;

   procedure Test_Tool_Bad_File (T : in out Test) is
      Result  : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " list Makefile", Result, 1);
      Util.Tests.Assert_Matches (T, "akt: the file is not a keystore",
                                 Result, "akt on an invalid file");
   end Test_Tool_Bad_File;

   procedure Test_Tool_Nested_Wallet (T : in out Test) is
      Path    : constant String := Util.Tests.Get_Path (TEST_WALLET_PATH);
      Result  : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " list " & Path & " -p mypassword", Result, 0);
      Util.Tests.Assert_Matches (T, "^property.*5.*",
                                 Result, "list command failed");
      Util.Tests.Assert_Matches (T, "wallet.*0 .*",
                                 Result, "list command failed");

      T.Execute (Tool & " get " & Path & " -p mypassword wallet", Result, 1);
      Util.Tests.Assert_Matches (T, "akt: no content for an item of type wallet",
                                 Result, "get command on wallet");
   end Test_Tool_Nested_Wallet;

   --  ------------------------------
   --  Test the OTP command.
   --  ------------------------------
   procedure Test_Tool_OTP (T : in out Test) is
      Ref_Path : constant String := Util.Tests.Get_Path (TEST_OTP_PATH);
      Path     : constant String := Util.Tests.Get_Test_Path (TEST_TOOL6_PATH);
      Result   : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " otp " & Ref_Path & " -p mypassword", Result, 0);
      Util.Tests.Assert_Matches (T, "GitHub:bob",
                                 Result, "otp command failed");

      T.Execute (Tool & " otp " & Ref_Path & " -p mypassword bob", Result, 0);
      Util.Tests.Assert_Matches (T, "GitHub:bob: code: [0-9]+",
                                 Result, "otp command failed");

      T.Execute (Tool & " otp " & Ref_Path & " -p mypassword harry", Result, 0);
      Util.Tests.Assert_Matches (T, "Gitlab:harry: code: [0-9]+",
                                 Result, "otp command failed");

      if Ada.Directories.Exists (Path) then
         Ada.Directories.Delete_File (Path);
      end if;

      --  Create keystore
      T.Execute (Tool & " create " & Path & " -p admin --counter-range 10:100", Result);
      Util.Tests.Assert_Equals (T, "", Result, "create command failed");
      T.Assert (Ada.Directories.Exists (Path),
                "Keystore file does not exist");

      T.Execute (Tool & " otp " & Path & " -p admin '"
                 & "otpauth://totp/Test:bob?secret=ONSWG4TFOQYTEMZU&issuer=Test'",
                 Result, 0);
      Util.Tests.Assert_Matches (T, "Code: [0-9]+",
                                 Result, "otp command failed");

      T.Execute (Tool & " otp " & Path & " -p admin '"
                 & "otpauth://totp/Unit:harry?secret=KNSWG4TFOQYTEMZU&issuer=Unit'",
                 Result, 0);
      Util.Tests.Assert_Matches (T, "Code: [0-9]+",
                                 Result, "otp command failed");

      T.Execute (Tool & " otp " & Path & " -p admin", Result, 0);
      Util.Tests.Assert_Matches (T, "Test:bob",
                                 Result, "otp command failed");
      Util.Tests.Assert_Matches (T, "Unit:harry",
                                 Result, "otp command failed");

   end Test_Tool_OTP;

   --  ------------------------------
   --  Test the OTP command with various errors.
   --  ------------------------------
   procedure Test_Tool_OTP_Error (T : in out Test) is
      Ref_Path : constant String := Util.Tests.Get_Path (TEST_OTP_PATH);
      Result   : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " otp " & Ref_Path & " -p mypassword bad-key", Result, 1);
      Util.Tests.Assert_Matches (T, "invalid secret key for 'Fake:bad-key'",
                                 Result, "otp command failed");

      T.Execute (Tool & " otp " & Ref_Path & " -p mypassword empty-secret", Result, 1);
      Util.Tests.Assert_Matches (T, "akt: invalid otpauth URI: missing 'secret'",
                                 Result, "otp command failed");

      T.Execute (Tool & " otp " & Ref_Path & " -p mypassword bad-algo", Result, 1);
      Util.Tests.Assert_Matches (T, "akt: algorithm 'SHA8' is not supported",
                                 Result, "otp command failed");

      T.Execute (Tool & " otp " & Ref_Path & " -p mypassword bad-digit-1", Result, 1);
      Util.Tests.Assert_Matches (T, "akt: invalid digits 'b'",
                                 Result, "otp command failed");

      T.Execute (Tool & " otp " & Ref_Path & " -p mypassword bad-digit-2", Result, 1);
      Util.Tests.Assert_Matches (T, "akt: invalid digits '0'",
                                 Result, "otp command failed");

      T.Execute (Tool & " otp " & Ref_Path & " -p mypassword bad-digit-3", Result, 1);
      Util.Tests.Assert_Matches (T, "akt: invalid digits '11'",
                                 Result, "otp command failed");
   end Test_Tool_OTP_Error;

   --  ------------------------------
   --  Test the genkey command.
   --  ------------------------------
   procedure Test_Tool_Genkey (T : in out Test) is
      Config_Path : constant String := Util.Tests.Get_Test_Path (TEST_CONFIG_PATH);
      Keys_Path   : constant String := Util.Tests.Get_Test_Path ("keys");
      Path        : constant String := Util.Tests.Get_Test_Path (TEST_TOOL7_PATH);
      Result      : Ada.Strings.Unbounded.Unbounded_String;
   begin
      if Ada.Directories.Exists (Keys_Path) then
         Ada.Directories.Delete_Tree (Keys_Path);
      end if;
      T.Execute (Tool & " --config " & Config_Path & " config keys " & Keys_Path,
                 Result, 0);
      Util.Tests.Assert_Equals (T, "", Result,
                                "Bad output for config command");
      T.Assert (Ada.Directories.Exists (Config_Path),
                "Config file '" & Config_Path & "' does not exist after test");

      --  Generate a first key.
      T.Execute (Tool & " --config " & Config_Path & " genkey mykey", Result, 0);
      Util.Tests.Assert_Equals (T, "", Result,
                                "Bad output for genkey command");
      T.Assert (Ada.Directories.Exists (Keys_Path),
                "Keys directory '" & Keys_Path & "' was not created");
      T.Assert (Ada.Directories.Exists (Keys_Path & "/mykey.key"),
                "Generated namedkey 'mykey' was not created");

      --  Generate a second key.
      T.Execute (Tool & " --config " & Config_Path & " genkey second", Result, 0);
      Util.Tests.Assert_Equals (T, "", Result,
                                "Bad output for genkey command");
      T.Assert (Ada.Directories.Exists (Keys_Path & "/mykey.key"),
                "Generated namedkey 'mykey' was not created");
      T.Assert (Ada.Directories.Exists (Keys_Path & "/second.key"),
                "Generated namedkey 'second' was not created");

      if Ada.Directories.Exists (Path) then
         Ada.Directories.Delete_File (Path);
      end if;

      --  Create keystore
      T.Execute (Tool & " --config " & Config_Path & " create " & Path
                 & " --wallet-key second "
                 & " --passkey mykey --counter-range 10:100", Result);
      Util.Tests.Assert_Equals (T, "", Result, "create command failed");
      T.Assert (Ada.Directories.Exists (Path),
                "Keystore file does not exist");

      --  Set a value in the keystore
      T.Execute (Tool & " --config " & Config_Path & " set " & Path
                 & " --wallet-key second "
                 & " --passkey mykey test secret-data", Result);
      Util.Tests.Assert_Equals (T, "", Result, "set command failed");

      --  Get the value from the keystore
      T.Execute (Tool & " --config " & Config_Path & " get -n " & Path
                 & " --wallet-key second "
                 & " --passkey mykey test", Result);
      Util.Tests.Assert_Equals (T, "secret-data", Result, "get command failed");

      --  Check reading the keystore with a wrong master key.
      T.Execute (Tool & " --config " & Config_Path & " get -n " & Path
                 & " --wallet-key mykey "
                 & " --passkey mykey test", Result, 1);
      Util.Tests.Assert_Matches (T, "invalid password to unlock the keystore file",
                                 Result, "get command failed");

      --  Likewise with a correct master key but invalid password key.
      T.Execute (Tool & " --config " & Config_Path & " get -n " & Path
                 & " --wallet-key second "
                 & " --passkey second test", Result, 1);
      Util.Tests.Assert_Matches (T, "invalid password to unlock the keystore file",
                                 Result, "get command failed");

   end Test_Tool_Genkey;

end Keystore.Tests;
