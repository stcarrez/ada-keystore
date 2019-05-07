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
with Interfaces.C.Strings;
with Ada.Directories;
with Ada.Strings.Unbounded;
with Util.Files;
with Util.Systems.Types;
with Util.Systems.Os;
package body AKT.Passwords.Files is

   type Provider (Len : Natural) is limited new AKT.Passwords.Provider with record
      Path : String (1 .. Len);
   end record;

   --  Get the password and return it as a secret key.
   overriding
   function Get_Password (From : in Provider) return Keystore.Secret_Key;

   --  ------------------------------
   --  Create a password provider that reads the file to build the password.
   --  ------------------------------
   function Create (Path : in String) return Provider_Access is
   begin
      return new Provider '(Len => Path'Length, Path => Path);
   end Create;

   --  ------------------------------
   --  Get the password and return it as a secret key.
   --  ------------------------------
   overriding
   function Get_Password (From : in Provider) return Keystore.Secret_Key is
      use type Interfaces.C.unsigned;

      Content : Ada.Strings.Unbounded.Unbounded_String;
      Path    : Interfaces.C.Strings.chars_ptr;
      Stat    : aliased Util.Systems.Types.Stat_Type;
      Res     : Integer;
   begin
      --  Verify that the file is readable only by the current user.
      Path := Interfaces.C.Strings.New_String (From.Path);
      Res := Util.Systems.Os.Sys_Stat (Path => Path,
                                       Stat => Stat'Access);
      Interfaces.C.Strings.Free (Path);
      if Res /= 0 then
         raise Keystore.Bad_Password with "Password file does not exist";
      end if;
      if (Stat.st_mode and 8#0077#) /= 0 then
         raise Keystore.Bad_Password with "Password file is not safe";
      end if;

      --  Verify that the parent directory is readable only by the current user.
      Path := Interfaces.C.Strings.New_String (Ada.Directories.Containing_Directory (From.Path));
      Res := Util.Systems.Os.Sys_Stat (Path => Path,
                                       Stat => Stat'Access);
      Interfaces.C.Strings.Free (Path);
      if Res /= 0 then
         raise Keystore.Bad_Password
         with "Directory that contains password file cannot be checked";
      end if;
      if (Stat.st_mode and 8#0077#) /= 0 then
         raise Keystore.Bad_Password
         with "Directory that contains password file is not safe";
      end if;

      Util.Files.Read_File (Path => From.Path,
                            Into => Content);
      return Keystore.Create (Ada.Strings.Unbounded.To_String (Content));
   end Get_Password;

end AKT.Passwords.Files;
