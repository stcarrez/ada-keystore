-----------------------------------------------------------------------
--  keystore-tests -- Tests for akt command
--  Copyright (C) 2019, 2020, 2023 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Util.Tests;
with Util.Systems.Os;
package Keystore.Tests is

   pragma Warnings (Off, "*condition is always*");

   function Is_Windows return Boolean is
     (Util.Systems.Os.Directory_Separator = '\');

   pragma Warnings (On, "*condition is always*");

   EXE   : constant String
     := (if Is_Windows then ".exe" else "");

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite);

   type Test is new Util.Tests.Test with null record;

   --  Test the akt help command.
   procedure Test_Tool_Help (T : in out Test);

   --  Test the akt keystore creation.
   procedure Test_Tool_Create (T : in out Test);
   procedure Test_Tool_Create_Error (T : in out Test);

   --  Test the akt keystore creation with password file.
   procedure Test_Tool_Create_Password_File (T : in out Test);
   procedure Test_Tool_Create_Password_Command (T : in out Test);

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
   procedure Test_Tool_Edit_Error (T : in out Test);

   --  Test the akt store and akt extract commands.
   procedure Test_Tool_Store_Extract (T : in out Test);
   procedure Test_Tool_Store_Extract_Tree (T : in out Test);

   --  Test the akt store command with errors.
   procedure Test_Tool_Store_Error (T : in out Test);
   procedure Test_Tool_Extract_Error (T : in out Test);

   --  Test the akt password-set command.
   procedure Test_Tool_Password_Set (T : in out Test);
   procedure Test_Tool_Password_Add_Limit (T : in out Test);

   --  Test the akt with an interactive password.
   procedure Test_Tool_Interactive_Password (T : in out Test);

   --  Test the akt with data blocks written in separate files.
   procedure Test_Tool_Separate_Data (T : in out Test);

   --  Test the akt config command.
   procedure Test_Tool_Set_Config (T : in out Test);

   --  Test the akt info command on several keystore files.
   procedure Test_Tool_Info (T : in out Test);
   procedure Test_Tool_Info_Error (T : in out Test);
   procedure Test_Tool_Info_Many_Keys (T : in out Test);
   procedure Test_Tool_List_Error (T : in out Test);

   --  Test the akt commands with --wallet-key-file
   procedure Test_Tool_With_Wallet_Key_File (T : in out Test);

   procedure Test_Tool_Corrupted_1 (T : in out Test);
   procedure Test_Tool_Corrupted_2 (T : in out Test);

   procedure Test_Tool_Missing_Storage (T : in out Test);

   procedure Test_Tool_Version (T : in out Test);

   procedure Test_Tool_Bad_File (T : in out Test);

   procedure Test_Tool_Nested_Wallet (T : in out Test);

   --  Test the OTP command.
   procedure Test_Tool_OTP (T : in out Test);

   --  Test the OTP command with various errors.
   procedure Test_Tool_OTP_Error (T : in out Test);

   --  Test the OTP command with interactive mode.
   procedure Test_Tool_OTP_Interactive (T : in out Test);

   --  Test the genkey command.
   procedure Test_Tool_Genkey (T : in out Test);

   procedure Store_Extract (T       : in out Test;
                            Command : in String;
                            Name    : in String;
                            Path    : in String);

end Keystore.Tests;
