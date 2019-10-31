-----------------------------------------------------------------------
--  keystore-passwords-unsafe -- Unsafe password provider
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
