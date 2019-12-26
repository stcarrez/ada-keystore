-----------------------------------------------------------------------
--  keystore-passwords-input -- Interactive based password provider
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
package Keystore.Passwords.Input is

   MAX_PASSWORD_LENGTH : constant := 1024;

   --  Create a password provider that asks interactively for the password.
   function Create (Message : in String;
                    Confirm : in Boolean) return Provider_Access;

end Keystore.Passwords.Input;
