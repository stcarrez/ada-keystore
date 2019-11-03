-----------------------------------------------------------------------
--  akt-commands-drivers -- Ada Keystore command driver
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
with Ada.Directories;
with Util.Files;
with Util.Strings;
with AKT.Configs;
package body AKT.Commands.Drivers is

   function Get_Help (Name   : in String;
                      Locale : in String) return String;

   --  ------------------------------
   --  Setup the command before parsing the arguments and executing it.
   --  ------------------------------
   overriding
   procedure Setup (Command : in out Command_Type;
                    Config  : in out GNAT.Command_Line.Command_Line_Configuration;
                    Context : in out Context_Type) is
   begin
      GC.Set_Usage (Config => Config,
                    Usage  => Command.Get_Name & " [arguments]",
                    Help   => Command.Get_Description);
      AKT.Commands.Setup (Config, Context);
   end Setup;

   function Get_Help (Name   : in String;
                      Locale : in String) return String is
      Pos : constant Natural := Util.Strings.Index (Locale, '_');
   begin
      if Pos > 0 then
         return AKT.Configs.RESOURCES & Locale (Locale'First .. Pos - 1) & "/" & Name & ".txt";
      elsif Locale'Length > 0 then
         return AKT.Configs.RESOURCES & Locale & "/" & Name & ".txt";
      else
         return AKT.Configs.RESOURCES & "en/" & Name & ".txt";
      end if;
   end Get_Help;

   --  ------------------------------
   --  Write the help associated with the command.
   --  ------------------------------
   overriding
   procedure Help (Command   : in out Command_Type;
                   Name      : in String;
                   Context   : in out Context_Type) is
      pragma Unreferenced (Command, Context);

      Path : constant String := Get_Help (Name, Intl.Current_Locale);
   begin
      if Ada.Directories.Exists (Path) then
         Util.Files.Read_File (Path    => Path,
                               Process => Ada.Text_IO.Put_Line'Access);
      else
         Util.Files.Read_File (Path    => Get_Help (Name, "en"),
                               Process => Ada.Text_IO.Put_Line'Access);
      end if;
   end Help;

end AKT.Commands.Drivers;
