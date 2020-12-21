-----------------------------------------------------------------------
--  keystore-files-tests -- Tests for keystore files
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

with Util.Tests;
package Keystore.Files.Tests is

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite);

   type Test is new Util.Tests.Test with null record;

   --  Test creation of a keystore and re-opening it.
   procedure Test_Create (T : in out Test);

   --  Test opening a keystore when some blocks are corrupted.
   procedure Test_Corruption (T : in out Test);

   --  Test adding values to a keystore.
   procedure Test_Add (T : in out Test);

   --  Test adding values and getting them back.
   procedure Test_Add_Get (T : in out Test);

   --  Test deleting values.
   procedure Test_Delete (T : in out Test);

   --  Test update values.
   procedure Test_Update (T : in out Test);

   --  Test update values in growing and descending sequences.
   procedure Test_Update_Sequence (T : in out Test);

   --  Test opening and closing keystore.
   procedure Test_Open_Close (T : in out Test);

   --  Test opening a keystore and listing the entries.
   procedure Test_List (T : in out Test);

   --  Test adding values that already exist.
   procedure Test_Add_Error (T : in out Test);

   --  Test changing the wallet password.
   procedure Test_Set_Key (T : in out Test);

   --  Test adding empty values to a keystore.
   procedure Test_Add_Empty (T : in out Test);

   --  Test getting values through an Output_Stream.
   procedure Test_Get_Stream (T : in out Test);

   --  Test setting values through an Input_Stream.
   procedure Test_Set_From_Stream (T : in out Test);
   procedure Test_Set_From_Larger_Stream (T : in out Test);

   --  Test updating values through an Input and Output_Stream.
   procedure Test_Update_Stream (T : in out Test);

   --  Test reading partial value starting at a given position.
   procedure Test_Read (T : in out Test);

   --  Test writing partial value starting at a given position.
   procedure Test_Write (T : in out Test);

   --  Perforamce test adding values.
   procedure Test_Perf_Add (T : in out Test);

   procedure Test_File_Stream (T     : in out Test;
                               Name  : in String;
                               Input : in String;
                               Create : in Boolean);

   --  Test setting and getting header data.
   procedure Test_Header_Data_1 (T : in out Test);
   procedure Test_Header_Data_10 (T : in out Test);
   procedure Test_Header_Data_Error (T : in out Test);
   procedure Test_Header_Data_Update (T : in out Test);

   --  Test creating a wallet.
   procedure Test_Add_Wallet (T : in out Test);
   procedure Test_Child_Wallet_Error (T : in out Test);

   --  Test operation on corrupted keystore.
   procedure Test_Corrupted_1 (T : in out Test);

end Keystore.Files.Tests;
