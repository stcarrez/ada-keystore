-----------------------------------------------------------------------
--  akt-passwords-files -- File based password provider
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
with Ada.Text_IO;
with Ada.Strings.Unbounded;
package body AKT.Passwords.Input is

   type Provider is limited new AKT.Passwords.Provider with record
      Confirm : Boolean := False;
   end record;

   --  Get the password and return it as a secret key.
   overriding
   function Get_Password (From : in Provider) return Keystore.Secret_Key;

   --  ------------------------------
   --  Create a password provider that asks interactively for the password.
   --  ------------------------------
   function Create (Confirm : in Boolean) return Provider_Access is
   begin
      return new Provider '(Confirm => Confirm);
   end Create;

   --  ------------------------------
   --  Get the password and return it as a secret key.
   --  ------------------------------
   overriding
   function Get_Password (From : in Provider) return Keystore.Secret_Key is
      pragma Unreferenced (From);

      Content : Ada.Strings.Unbounded.Unbounded_String;
      C       : Character;
   begin
      Ada.Text_IO.Put_Line ("Enter password:");
      while not Ada.Text_IO.End_Of_File loop
         Ada.Text_IO.Get_Immediate (C);
         exit when C < ' ';
         Ada.Strings.Unbounded.Append (Content, C);
      end loop;

      return Keystore.Create (Ada.Strings.Unbounded.To_String (Content));
   end Get_Password;

end AKT.Passwords.Input;
