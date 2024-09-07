-----------------------------------------------------------------------
--  keystore-passwords-unsafe -- Unsafe password provider
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
package Keystore.Passwords.Unsafe is

   --  Create a unsafe command line base password provider.
   function Create (Password : in String) return Provider_Access;

end Keystore.Passwords.Unsafe;
