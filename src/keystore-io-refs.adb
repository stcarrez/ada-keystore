-----------------------------------------------------------------------
--  keystore-io-refs -- IO stream reference holder
--  Copyright (C) 2019, 2020 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Ada.Unchecked_Deallocation;
package body Keystore.IO.Refs is

   use type Util.Concurrent.Counters.Counter_Access;

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
