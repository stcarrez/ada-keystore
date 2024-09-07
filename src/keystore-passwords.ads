-----------------------------------------------------------------------
--  keystore-passwords -- Password provider
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

package Keystore.Passwords is

   type Provider is limited interface;

   type Provider_Access is access all Provider'Class;

   --  Get the password through the Getter operation.
   procedure Get_Password (From   : in Provider;
                           Getter : not null
                           access procedure (Password : in Secret_Key)) is abstract;

   subtype Tag_Type is Interfaces.Unsigned_32;

   type Slot_Provider is limited interface and Provider;

   function Get_Tag (From : in Slot_Provider) return Tag_Type is abstract;

   function Has_Password (From : in Slot_Provider) return Boolean is abstract;

   procedure Next (From : in out Slot_Provider) is abstract;

   --  Get the key and IV through the Getter operation.
   procedure Get_Key (From   : in Slot_Provider;
                      Getter : not null access procedure (Key  : in Secret_Key;
                                                          IV   : in Secret_Key)) is abstract;

   procedure To_Provider (Secret  : in Secret_Key;
                          Process : not null access procedure (P : in out Provider'Class));

private

   type Internal_Key_Provider is limited interface;

   procedure Save_Key (Provider : in Internal_Key_Provider;
                       Data     : out Ada.Streams.Stream_Element_Array) is abstract;

   type Default_Provider (Len : Key_Length) is limited new Provider with record
      Password : Keystore.Secret_Key (Len);
   end record;
   type Default_Provider_Access is access all Default_Provider'Class;

   --  Get the password through the Getter operation.
   overriding
   procedure Get_Password (From   : in Default_Provider;
                           Getter : not null access procedure (Password : in Secret_Key));

   --  Create a password provider.
   function Create (Password : in out Ada.Streams.Stream_Element_Array) return Provider_Access;

end Keystore.Passwords;
