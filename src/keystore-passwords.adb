-----------------------------------------------------------------------
--  keystore-passwords -- Password provider
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

package body Keystore.Passwords is

   procedure To_Provider (Secret  : in Secret_Key;
                          Process : not null access procedure (P : in out Provider'Class)) is

      type Secret_Provider is new Provider with null record;

      overriding
      procedure Get_Password (From   : in Secret_Provider;
                              Getter : not null access procedure (Password : in Secret_Key));
      overriding
      procedure Get_Password (From   : in Secret_Provider;
                              Getter : not null access procedure (Password : in Secret_Key)) is
         pragma Unreferenced (From);
      begin
         Getter (Secret);
      end Get_Password;

      P : Secret_Provider;
   begin
      Process (P);
   end To_Provider;

   --  ------------------------------
   --  Get the password through the Getter operation.
   --  ------------------------------
   overriding
   procedure Get_Password (From   : in Default_Provider;
                           Getter : not null access procedure (Password : in Secret_Key)) is
   begin
      Getter (From.Password);
   end Get_Password;

   --  ------------------------------
   --  Create a password provider.
   --  ------------------------------
   function Create (Password : in out Ada.Streams.Stream_Element_Array) return Provider_Access is
      P : constant Default_Provider_Access
        := new Default_Provider '(Len => Password'Length, others => <>);
   begin
      Util.Encoders.Create (Password, P.Password);
      Password := (others => 0);
      return P.all'Access;
   end Create;

end Keystore.Passwords;
