-----------------------------------------------------------------------
--  akt-commands-drivers -- Ada Keystore command driver
--  Copyright (C) 2019, 2023 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with Ada.Directories;
with Ada.Command_Line;
with Util.Files;
with Util.Strings;
with AKT.Configs;
package body AKT.Commands.Drivers is

   function Get_Help (Dir    : in String;
                      Name   : in String;
                      Locale : in String) return String;
   function Get_Resources_Directory return String;

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

   function Get_Resources_Directory return String is
      Dir : constant String := AKT_Resources.Prefix_Path;
   begin
      if Ada.Directories.Exists (Dir & AKT.Configs.RESOURCES) then
         return Dir & AKT.Configs.RESOURCES;
      end if;
      declare
         Name : constant String := Ada.Command_Line.Command_Name;
         Path : constant String := Ada.Directories.Containing_Directory (Name);
         Dir  : constant String := Ada.Directories.Containing_Directory (Path);
      begin
         return Dir & AKT.Configs.RESOURCES;
      end;
   end Get_Resources_Directory;

   function Get_Help (Dir    : in String;
                      Name   : in String;
                      Locale : in String) return String is
      Pos : constant Natural := Util.Strings.Index (Locale, '_');
   begin
      if Pos > 0 then
         return Dir & Locale (Locale'First .. Pos - 1) & "/" & Name & ".txt";
      elsif Locale'Length > 0 then
         return Dir & Locale & "/" & Name & ".txt";
      else
         return Dir & "en/" & Name & ".txt";
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

      Dir  : constant String := Get_Resources_Directory;
      Path : constant String := Get_Help (Dir, Name, Intl.Current_Locale);
   begin
      if Ada.Directories.Exists (Path) then
         Util.Files.Read_File (Path    => Path,
                               Process => Util.Commands.Put_Raw_Line'Access);
      else
         Util.Files.Read_File (Path    => Get_Help (Dir, Name, "en"),
                               Process => Util.Commands.Put_Raw_Line'Access);
      end if;
   end Help;

end AKT.Commands.Drivers;
