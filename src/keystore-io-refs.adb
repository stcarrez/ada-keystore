-----------------------------------------------------------------------
--  keystore-io-refs -- IO stream reference holder
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
package body Keystore.IO.Refs is

   use type Util.Concurrent.Counters.Counter_Access;

   function Is_Null (Object : in Stream_Ref) return Boolean is
   begin
      return Object.Stream = null;
   end Is_Null;

   function Create (Stream : in Wallet_Stream_Access) return Stream_Ref is
   begin
      return Result : Stream_Ref do
         Result.Stream := Stream;
         Result.Counter := new Util.Concurrent.Counters.Counter;
         Util.Concurrent.Counters.Increment (Result.Counter.all);
      end return;
   end Create;

   function Value (Object : in Stream_Ref) return Wallet_Stream_Access is
   begin
      return Object.Stream;
   end Value;

   procedure Free is
     new Ada.Unchecked_Deallocation (Object => Util.Concurrent.Counters.Counter,
                                     Name   => Util.Concurrent.Counters.Counter_Access);

   procedure Free is
     new Ada.Unchecked_Deallocation (Object => IO.Wallet_Stream'Class,
                                     Name   => IO.Wallet_Stream_Access);

   overriding
   procedure Finalize (Object : in out Stream_Ref) is
      Release : Boolean;
   begin
      if Object.Counter /= null then
         Util.Concurrent.Counters.Decrement (Object.Counter.all, Release);
         if Release then
            Object.Stream.Close;
            Free (Object.Stream);
            Free (Object.Counter);
         else
            Object.Stream := null;
            Object.Counter := null;
         end if;
      end if;
   end Finalize;

   overriding
   procedure Adjust (Object : in out Stream_Ref) is
   begin
      if Object.Counter /= null then
         Util.Concurrent.Counters.Increment (Object.Counter.all);
      end if;
   end Adjust;

end Keystore.IO.Refs;
