-----------------------------------------------------------------------
--  keystore-passwords-unsafe -- Unsafe password provider
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
package body Keystore.Passwords.Unsafe is

   type Provider (Len : Natural) is limited new Keystore.Passwords.Provider with record
      Password : String (1 .. Len);
   end record;

   --  Get the password through the Getter operation.
   overriding
   procedure Get_Password (From   : in Provider;
                           Getter : not null access procedure (Password : in Secret_Key));

   --  ------------------------------
   --  Create a unsafe command line base password provider.
   --  ------------------------------
   function Create (Password : in String) return Provider_Access is
   begin
      return new Provider '(Len      => Password'Length,
                            Password => Password);
   end Create;

   --  ------------------------------
   --  Get the password through the Getter operation.
   --  ------------------------------
   overriding
   procedure Get_Password (From   : in Provider;
                           Getter : not null access procedure (Password : in Secret_Key)) is
   begin
      Getter (Keystore.Create (From.Password));
   end Get_Password;

end Keystore.Passwords.Unsafe;
