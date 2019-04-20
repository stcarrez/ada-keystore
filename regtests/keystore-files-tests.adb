-----------------------------------------------------------------------
--  keystore-files-tests -- Tests for files
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

with Ada.Exceptions;
with Util.Test_Caller;
with Keystore.IO.Files;
package body Keystore.Files.Tests is

   package Caller is new Util.Test_Caller (Test, "files");

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite) is
   begin
      Caller.Add_Test (Suite, "Test Keystore.Files.Create+Open",
                       Test_Create'Access);
      Caller.Add_Test (Suite, "Test Keystore.Add",
                       Test_Add'Access);
      Caller.Add_Test (Suite, "Test Keystore.Get",
                       Test_Add_Get'Access);
      Caller.Add_Test (Suite, "Test Keystore.Open (Corrupted keystore)",
                       Test_Corruption'Access);
      Caller.Add_Test (Suite, "Test Keystore.List",
                       Test_List'Access);
   end Add_Tests;

   --  ------------------------------
   --  Test creation of a keystore and re-opening it.
   --  ------------------------------
   procedure Test_Create (T : in out Test) is
      Path     : constant String := Util.Tests.Get_Test_Path ("regtests/result/test-create.ks");
      Password : Keystore.Secret_Key := Keystore.Create ("mypassword");
   begin
      declare
         W        : Keystore.Files.Wallet_File;
      begin
         W.Create (Path => Path, Password => Password);
      end;
      declare
         Wread    : Keystore.Files.Wallet_File;
      begin
         Wread.Open (Path => Path, Password => Password);
      end;
      declare
         Wread    : Keystore.Files.Wallet_File;
         Bad      : Keystore.Secret_Key := Keystore.Create ("mypassword-bad");
      begin
         Wread.Open (Path => Path, Password => Bad);
         T.Fail ("No exception raised");

      exception
         when Bad_Password =>
            null;
      end;
   end Test_Create;

   --  ------------------------------
   --  Test opening a keystore when some blocks are corrupted.
   --  ------------------------------
   procedure Test_Corruption (T : in out Test) is
      use type IO.Block_Index;
      use type IO.Block_Count;

      procedure Corrupt (Block : in IO.Block_Number;
                         Pos   : in IO.Block_Index);

      Path         : constant String
        := Util.Tests.Get_Path ("regtests/files/test-keystore.ks");

      Corrupt_Path : constant String
        := Util.Tests.Get_Test_Path ("regtests/result/test-corrupt.ks");

      procedure Corrupt (Block : in IO.Block_Number;
                         Pos   : in IO.Block_Index) is
         use type Ada.Streams.Stream_Element;

         Source_File  : IO.Files.Block_IO.File_Type;
         Corrupt_File : IO.Files.Block_IO.File_Type;
         Data         : IO.Block_Type;
         Current      : IO.Block_Number := 1;
      begin
         IO.Files.Block_IO.Open (Name => Path,
                                 File => Source_File,
                                 Mode => IO.Files.Block_IO.In_File);
         IO.Files.Block_IO.Create (Name => Corrupt_Path,
                                   File => Corrupt_File,
                                   Mode => IO.Files.Block_IO.Inout_File);
         while not IO.Files.Block_IO.End_Of_File (Source_File) loop
            IO.Files.Block_IO.Read (Source_File, Data);
            if Current = Block then
               Data (Pos) := Data (Pos) xor 1;
            end if;
            IO.Files.Block_IO.Write (Corrupt_File, Data);
            Current := Current + 1;
         end loop;
         IO.Files.Block_IO.Close (Source_File);
         IO.Files.Block_IO.Close (Corrupt_File);
      end Corrupt;

      Password : Keystore.Secret_Key := Keystore.Create ("mypassword");
   begin
      for Block in IO.Block_Number (1) .. 3 loop
         for I in 1 .. IO.Block_Index'Last / 17 loop
            declare
               Pos : constant IO.Block_Index := I * 17;
               W   : Keystore.Files.Wallet_File;
            begin
               Corrupt (Block, Pos);
               W.Open (Password => Password,
                       Path     => Corrupt_Path);
               T.Fail ("No corruption detected block" & IO.Block_Number'Image (Block)
                       & " at" & IO.Block_Index'Image (Pos));

            exception
               when Keystore.Corrupted =>
                  null;

               when Keystore.Invalid_Block =>
                  null;

               when E : others =>
                  T.Fail ("Exception not expected: " & Ada.Exceptions.Exception_Name (E));
            end;
         end loop;
      end loop;
   end Test_Corruption;

   --  ------------------------------
   --  Test adding values to a keystore.
   --  ------------------------------
   procedure Test_Add (T : in out Test) is
      Path     : constant String := Util.Tests.Get_Test_Path ("regtests/result/test-add.ks");
      Password : Keystore.Secret_Key := Keystore.Create ("mypassword");
   begin
      declare
         W        : Keystore.Files.Wallet_File;
      begin
         W.Create (Path => Path, Password => Password);
         --  W.Add ("my-secret", "the secret");
         --  T.Assert (W.Contains ("my-secret"), "Property not contained in wallet");
      end;
      declare
         W        : Keystore.Files.Wallet_File;
      begin
         W.Open (Path => Path, Password => Password);
         W.Add ("my-secret", "the secret");
         T.Assert (W.Contains ("my-secret"), "Property not contained in wallet");
      end;

      declare
         W        : Keystore.Files.Wallet_File;
      begin
         W.Open (Path => Path, Password => Password);
         T.Assert (W.Contains ("my-secret"), "Property not contained in wallet (load)");

         Util.Tests.Assert_Equals (T, "the secret", W.Get ("my-secret"),
                                   "Property cannot be retrieved from keystore");
         W.Add ("my-second-secret", "the second-secret");
         T.Assert (W.Contains ("my-second-secret"), "Property not contained in wallet");
         T.Assert (W.Contains ("my-secret"), "Property not contained in wallet");
      end;

   end Test_Add;

   --  ------------------------------
   --  Test adding values and getting them back.
   --  ------------------------------
   procedure Test_Add_Get (T : in out Test) is
      Path     : constant String := Util.Tests.Get_Test_Path ("regtests/result/test-add-get.ks");
      Password : Keystore.Secret_Key := Keystore.Create ("mypassword-add-get");
   begin
      declare
         W        : Keystore.Files.Wallet_File;
      begin
         W.Create (Path => Path, Password => Password);
         --  W.Add ("my-secret-add-get", "the secret add-get");
         --  T.Assert (W.Contains ("my-secret-add-get"), "Property not contained in wallet");
      end;

      for Pass in 1 .. 10 loop
         declare
            W        : Keystore.Files.Wallet_File;
         begin
            W.Open (Path => Path, Password => Password);
            --  T.Assert (W.Contains ("my-secret-add-get"),
            --          "Property not contained in wallet (load)");

            --  Util.Tests.Assert_Equals (T, "the secret add-get", W.Get("my-secret-add-get"),
            --                          "Property cannot be retrieved from keystore");
            W.Add ("my-second-secret " & Positive'Image (Pass),
                   "the second-secret padd " & Positive'Image (Pass));
            --  T.Assert (W.Contains ("my-second-secret"), "Property not contained in wallet");
            --  T.Assert (W.Contains ("my-secret"), "Property not contained in wallet");

            for Check in 1 .. Pass loop
               T.Assert (W.Contains ("my-second-secret " & Positive'Image (Check)),
                         "Property not contained in wallet " & Positive'Image (Check));
               Util.Tests.Assert_Equals (T, "the second-secret padd " & Positive'Image (Check),
                                         W.Get ("my-second-secret " & Positive'Image (Check)),
                                         "Cannot get property " & Positive'Image (Check));
            end loop;
         end;
      end loop;

   end Test_Add_Get;

   --  ------------------------------
   --  Test opening a keystore and listing the entries.
   --  ------------------------------
   procedure Test_List (T : in out Test) is
      procedure Verify_Entry (Name : in String; Size : in Integer);

      Path     : constant String := Util.Tests.Get_Test_Path ("regtests/files/test-keystore.ks");
      Password : Keystore.Secret_Key := Keystore.Create ("mypassword");
      W        : Keystore.Files.Wallet_File;
      Items    : Keystore.Entry_Map;

      procedure Verify_Entry (Name : in String; Size : in Integer) is
         Value : Keystore.Entry_Info;
      begin
         T.Assert (Items.Contains (Name), "Item " & Name & " should be in the wallet list");
         T.Assert (W.Contains (Name), "Wallet should contain:" & Name);

         Value := Items.Element (Name);
         Util.Tests.Assert_Equals (T, Size, Value.Size, "Item " & Name & " has invalid size");

         T.Assert (Value.Kind = Keystore.T_STRING, "Item " & Name & " should be a T_STRING");
      end Verify_Entry;

   begin
      W.Open (Path => Path, Password => Password);
      W.List (Items);
      Verify_Entry ("list-1", 63);
      Verify_Entry ("list-2", 64);
      Verify_Entry ("list-3", 39);
      Verify_Entry ("list-4", 42);
   end Test_List;

end Keystore.Files.Tests;
