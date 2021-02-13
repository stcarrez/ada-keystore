-----------------------------------------------------------------------
--  keystore-gpg_tests -- Test AKT with GPG2
--  Copyright (C) 2020 Stephane Carrez
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
with Util.Test_Caller;
with Util.Log.Loggers;
with Util.Processes;
with Util.Streams.Buffered;
with Util.Streams.Pipes;
package body Keystore.Fuse_Tests is

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Keystore.Fuse_Tests");

   CHECK_MOUNT_PATH : constant String := "regtests/files/check-mount.sh";

   package Caller is new Util.Test_Caller (Test, "AKT.Fuse");

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite) is
   begin
      Caller.Add_Test (Suite, "Test AKT.Commands.Mount",
                       Test_Mount'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Mount (Fill)",
                       Test_Mount_Fill'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Mount (Clean)",
                       Test_Mount_Clean'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Mount (Check)",
                       Test_Mount_Check'Access);
      Caller.Add_Test (Suite, "Test AKT.Commands.Mount (Stress)",
                       Test_Mount_Stress'Access);
   end Add_Tests;

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

   --  ------------------------------
   --  Test the akt keystore creation.
   --  ------------------------------
   procedure Test_Mount (T : in out Test) is
      Tool   : constant String := Util.Tests.Get_Path (CHECK_MOUNT_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      --  Create keystore
      T.Execute (Tool & " START", Result);
      Util.Tests.Assert_Matches (T, "PASS", Result, "akt keystore creation failed");
   end Test_Mount;

   --  ------------------------------
   --  Test the akt mount and filling the keystore.
   --  ------------------------------
   procedure Test_Mount_Fill (T : in out Test) is
      Tool   : constant String := Util.Tests.Get_Path (CHECK_MOUNT_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " FILL", Result);
      Util.Tests.Assert_Matches (T, "PASS", Result,
                                 "akt keystore mount+fill failed");
   end Test_Mount_Fill;

   --  ------------------------------
   --  Test the akt mount and cleaning the keystore.
   --  ------------------------------
   procedure Test_Mount_Clean (T : in out Test) is
      Tool   : constant String := Util.Tests.Get_Path (CHECK_MOUNT_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " CLEAN", Result);
      Util.Tests.Assert_Matches (T, "PASS", Result,
                                 "akt keystore mount+clean failed");
   end Test_Mount_Clean;

   --  ------------------------------
   --  Test the akt mount and checking its content.
   --  ------------------------------
   procedure Test_Mount_Check (T : in out Test) is
      Tool   : constant String := Util.Tests.Get_Path (CHECK_MOUNT_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " CHECK", Result);
      Util.Tests.Assert_Matches (T, "PASS", Result,
                                 "akt keystore mount+check after stress failed");
   end Test_Mount_Check;

   --  ------------------------------
   --  Test the akt mount and stressing the filesystem.
   --  ------------------------------
   procedure Test_Mount_Stress (T : in out Test) is
      Tool   : constant String := Util.Tests.Get_Path (CHECK_MOUNT_PATH);
      Result : Ada.Strings.Unbounded.Unbounded_String;
   begin
      T.Execute (Tool & " BIG", Result);
      Util.Tests.Assert_Matches (T, "PASS", Result,
                                 "akt keystore mount+check after stress failed");
   end Test_Mount_Stress;

end Keystore.Fuse_Tests;
