-----------------------------------------------------------------------
--  akt-passwords -- Password provider
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

with Keystore;
package AKT.Passwords is

   type Provider is limited interface;

   type Provider_Access is access all Provider'Class;

   --  Get the password and return it as a secret key.
   function Get_Password (From : in Provider) return Keystore.Secret_Key is abstract;

end AKT.Passwords;
