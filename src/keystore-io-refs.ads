-----------------------------------------------------------------------
--  keystore-io-refs -- IO stream reference holder
--  Copyright (C) 2019, 2020 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
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
