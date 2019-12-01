-----------------------------------------------------------------------
--  keystore-passwords -- Password provider
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

end Keystore.Passwords;
