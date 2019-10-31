-----------------------------------------------------------------------
--  keystore-tools-tests -- Tests for files
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

with Ada.Directories;
with Util.Test_Caller;
with Util.Strings;
with Keystore.Files;
package body Keystore.Tools.Tests is

   use Ada.Directories;
   use type Interfaces.Unsigned_64;

   package Caller is new Util.Test_Caller (Test, "Files");

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite) is
   begin
      Caller.Add_Test (Suite, "Test Keystore.Files.Create+Open",
                       Test_Store_Directory'Access);
   end Add_Tests;

   --  ------------------------------
   --  Test storing a directory tree
   --  ------------------------------
   procedure Test_Store_Directory (T : in out Test) is
      function Filter (Ent : in Directory_Entry_Type) return Boolean;

      function Filter (Ent : in Directory_Entry_Type) return Boolean is
         Name  : constant String := Ada.Directories.Simple_Name (Ent);
         Kind  : constant File_Kind := Ada.Directories.Kind (Ent);
      begin
         if Kind = Ada.Directories.Ordinary_File then
            return Util.Strings.Ends_With (Name, ".ads");
         else
            return Name /= ".git" and Name /= "result";
         end if;
      end Filter;

      Path     : constant String := Util.Tests.Get_Test_Path ("regtests/result/test-store.akt");
      Password : Keystore.Secret_Key := Keystore.Create ("mypassword");
      Config   : Keystore.Wallet_Config := Unsecure_Config;
   begin
      declare
         W        : Keystore.Files.Wallet_File;
      begin
         Config.Overwrite := True;
         W.Create (Path => Path, Password => Password, Config => Config);
         Keystore.Tools.Store (Wallet  => W,
                               Path    => ".",
                               Prefix  => "store/",
                               Pattern => "*",
                               Filter  => Filter'Access);
      end;
      declare
         procedure Check (Name : in String);

         W        : Keystore.Files.Wallet_File;

         procedure Check (Name : in String) is
            Item     : Keystore.Entry_Info;
         begin
            Item := W.Find (Name);
            T.Assert (Item.Size > 8192, "Invalid item size for " & Name);
            T.Assert (Item.Size < 128 * 1024, "Invalid item size for " & Name);
            T.Assert (Item.Block_Count > 2, "Invalid item for " & Name);
            T.Assert (Item.Kind = T_FILE, "Invalid item type for " & Name);
         end Check;

      begin
         W.Open (Password => Password, Path => Path);
         Check ("store/src/keystore.ads");
         Check ("store/src/keystore-repository.ads");
         Check ("store/obj/b__akt-main.ads");
      end;
   end Test_Store_Directory;

end Keystore.Tools.Tests;
