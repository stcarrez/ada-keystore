-----------------------------------------------------------------------
--  keystore-io-tests -- Tests for keystore IO
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

with Util.Test_Caller;
with Keystore.IO.Files;
with Keystore.Buffers;
with Keystore.Passwords.GPG;
with Keystore.Repository;
with Keystore.IO.Refs;
package body Keystore.Coverage is

   --  A fake type to make sure execute generated compiler code for <T>DF() operation
   --  (these functions are used for deep finalization).
   type Deep_Finalization_Coverage is limited record
      Stream  : Keystore.IO.Files.Wallet_Stream;
      Context : Keystore.Passwords.GPG.Context_Type;
      Config  : Keystore.Wallet_Config;
      Repo    : Keystore.Repository.Wallet_Repository;
      Ref     : Keystore.IO.Refs.Stream_Ref;
      Block   : Keystore.Buffers.Storage_Block;
      Buf     : Keystore.Buffers.Data_Buffer_Type;
      Storage : Keystore.Buffers.Storage_Buffer;
   end record;

   package Caller is new Util.Test_Caller (Test, "Keystore.Coverage");

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite) is
   begin
      Caller.Add_Test (Suite, "Test Keystore.Coverage",
                       Test_Deep_Coverage'Access);
   end Add_Tests;

   procedure Test_Deep_Coverage (T : in out Test) is
      Item : Deep_Finalization_Coverage;
   begin
      Item.Config := Keystore.Secure_Config;
      T.Assert (Item'Size > 0, "Compiler error!!!!");
   end Test_Deep_Coverage;

end Keystore.Coverage;
