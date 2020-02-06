-----------------------------------------------------------------------
--  keystore-io-refs -- IO stream reference holder
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

private with Util.Concurrent.Counters;
private with Ada.Finalization;
package Keystore.IO.Refs is

   type Stream_Ref is tagged private;

   function Create (Stream : in Wallet_Stream_Access) return Stream_Ref;

   function Value (Object : in Stream_Ref) return Wallet_Stream_Access;

   Null_Ref : constant Stream_Ref;

private

   type Stream_Ref is new Ada.Finalization.Controlled with record
      Stream  : Wallet_Stream_Access;
      Counter : Util.Concurrent.Counters.Counter_Access;
   end record;

   overriding
   procedure Finalize (Object : in out Stream_Ref);

   overriding
   procedure Adjust (Object : in out Stream_Ref);

   Null_Ref : constant Stream_Ref := Stream_Ref '(Ada.Finalization.Controlled with
                                                  Stream => null, Counter => null);

end Keystore.IO.Refs;
