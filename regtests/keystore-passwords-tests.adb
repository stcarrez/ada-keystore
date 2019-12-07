-----------------------------------------------------------------------
--  keystore-passwords-tests -- Tests for Keystore.Passwords
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

with Ada.Unchecked_Deallocation;
with Ada.Streams.Stream_IO;
with Util.Test_Caller;
with Util.Encoders.SHA256;
with Util.Encoders.HMAC.SHA256;
with Keystore.Passwords.Keys;
with Keystore.Passwords.Files;
package body Keystore.Passwords.Tests is

   use type Ada.Streams.Stream_Element_Array;

   package Caller is new Util.Test_Caller (Test, "AKT.Passwords");

   function Hash (Provider : in Keys.Key_Provider_Access)
                  return Util.Encoders.SHA256.Hash_Array;

   procedure Free is
     new Ada.Unchecked_Deallocation (Object => Keys.Key_Provider'Class,
                                     Name   => Keys.Key_Provider_Access);

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite) is
   begin
      Caller.Add_Test (Suite, "Test Keystore.Passwords.Files",
                       Test_File_Password'Access);
   end Add_Tests;

   function Hash (Provider : in Keys.Key_Provider_Access)
                  return Util.Encoders.SHA256.Hash_Array is
      Context : Util.Encoders.HMAC.SHA256.Context;
      Key     : Secret_Key (Length => 32);
      IV      : Secret_Key (Length => 16);
      Sign    : Secret_Key (Length => 32);
      Result  : Util.Encoders.SHA256.Hash_Array;
   begin
      Provider.Get_Keys (Key, IV, Sign);
      Util.Encoders.HMAC.SHA256.Set_Key (Context, Key);
      Util.Encoders.HMAC.SHA256.Update (Context, IV);
      Util.Encoders.HMAC.SHA256.Update (Context, Sign);
      Util.Encoders.HMAC.SHA256.Finish (Context, Result);
      return Result;
   end Hash;

   --  ------------------------------
   --  Test the using the Passwords.Files
   --  ------------------------------
   procedure Test_File_Password (T : in out Test) is
      Path      : constant String := Util.Tests.Get_Test_Path ("regtests/result/pass/key1.bin");
      Provider1 : Keys.Key_Provider_Access;
      Provider2 : Keys.Key_Provider_Access;
      Hash1     : Util.Encoders.SHA256.Hash_Array;
      Hash2     : Util.Encoders.SHA256.Hash_Array;
      File      : Ada.Streams.Stream_IO.File_Type;
   begin
      Provider1 := Files.Generate (Path);
      Provider2 := Files.Create (Path);
      Hash1 := Hash (Provider1);
      Hash2 := Hash (Provider2);
      T.Assert (Hash1 = Hash2, "Generate and Create are inconsistent");

      Free (Provider1);

      Provider1 := Files.Generate (Path);
      Hash1 := Hash (Provider1);
      T.Assert (Hash1 /= Hash2, "Generate and Create are inconsistent");

      Free (Provider1);
      Free (Provider2);

      Ada.Streams.Stream_IO.Create (File, Ada.Streams.Stream_IO.Out_File, Path);
      Ada.Streams.Stream_IO.Close (File);
      begin
         Provider2 := Files.Create (Path);
         T.Fail ("No exception raised for an empty file");

      exception
         when Bad_Password =>
            null;
      end;

      Ada.Streams.Stream_IO.Create (File, Ada.Streams.Stream_IO.Out_File, Path);
      for I in 1 .. 200 loop
         Ada.Streams.Stream_IO.Write (File, Hash1);
      end loop;
      Ada.Streams.Stream_IO.Close (File);

      begin
         Provider2 := Files.Create (Path);
         T.Fail ("No exception raised for a big file");

      exception
         when Bad_Password =>
            null;
      end;

      begin
         Provider2 := Files.Create ("Makefile.conf");
         T.Fail ("No exception raised for a file stored in an unprotected dir");

      exception
         when Bad_Password =>
            null;
      end;
   end Test_File_Password;

end Keystore.Passwords.Tests;
