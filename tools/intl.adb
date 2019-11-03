-----------------------------------------------------------------------
--  intl -- Small libintl binding
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
package body Intl is

   function Sys_Gettext (Msg : in String) return Interfaces.C.Strings.chars_ptr
     with Import => True, Convention => C, Link_Name => "gettext";

   procedure Sys_Textdomain (Domain : in String)
     with Import => True, Convention => C, Link_Name => "textdomain";

   procedure Sys_Bindtextdomain (Domain : in String; Dirname : in String)
     with Import => True, Convention => C, Link_Name => "bindtextdomain";

   function Sys_Setlocale (Category : in Integer; Locale : in String)
                           return Interfaces.C.Strings.chars_ptr
     with Import => True, Convention => C, Link_Name => "setlocale";

   function Gettext (Message : in String) return String is
   begin
      return Interfaces.C.Strings.Value (Sys_Gettext (Message & ASCII.NUL));
   end Gettext;

   LC_ALL : constant Integer := 6;
   Locale : Interfaces.C.Strings.chars_ptr;

   procedure Initialize (Domain  : in String;
                         Dirname : in String) is
   begin
      Locale := Sys_Setlocale (LC_ALL, "" & ASCII.NUL);
      Sys_Textdomain (Domain & ASCII.NUL);
      Sys_Bindtextdomain (Domain & ASCII.NUL, Dirname & ASCII.NUL);
   end Initialize;

   function Current_Locale return String is
      use type Interfaces.C.Strings.chars_ptr;
   begin
      if Locale = Interfaces.C.Strings.Null_Ptr then
         return "C";
      else
         return Interfaces.C.Strings.Value (Locale);
      end if;
   end Current_Locale;

end Intl;
