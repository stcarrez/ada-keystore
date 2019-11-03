-----------------------------------------------------------------------
--  akt-commands-edit -- Edit content in keystore
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
with Ada.Directories;
with Ada.Environment_Variables;
with Ada.Command_Line;
with Interfaces.C.Strings;
with Util.Files;
with Util.Processes;
with Util.Systems.Os;
with Util.Systems.Types;
with Util.Streams.Raw;
with Keystore.Random;
package body AKT.Commands.Edit is

   use GNAT.Strings;

   procedure Export_Value (Context : in out Context_Type;
                           Name    : in String;
                           Path    : in String);

   procedure Import_Value (Context : in out Context_Type;
                           Name    : in String;
                           Path    : in String);

   procedure Make_Directory (Path : in String);

   --  ------------------------------
   --  Export the named value from the wallet to the external file.
   --  The file is created and given read-write access to the current user only.
   --  ------------------------------
   procedure Export_Value (Context : in out Context_Type;
                           Name    : in String;
                           Path    : in String) is
      use Util.Systems.Os;
      use type Interfaces.C.int;
      use type Util.Systems.Types.File_Type;

      Fd   : Util.Systems.Os.File_Type;
      File : Util.Streams.Raw.Raw_Stream;
      P    : Interfaces.C.Strings.chars_ptr := Interfaces.C.Strings.New_String (Path);
   begin
      Fd := Util.Systems.Os.Sys_Open (Path  => P,
                                      Flags => O_CREAT + O_WRONLY + O_TRUNC,
                                      Mode  => 8#600#);
      Interfaces.C.Strings.Free (P);
      if Fd < 0 then
         AKT.Commands.Log.Error (-("Cannot create file for the editor"));
         raise Error;
      end if;
      File.Initialize (Fd);
      if Context.Wallet.Contains (Name) then
         Context.Wallet.Get (Name, File);
      end if;
   end Export_Value;

   procedure Import_Value (Context : in out Context_Type;
                           Name    : in String;
                           Path    : in String) is
      use Util.Systems.Os;
      use type Util.Systems.Types.File_Type;

      Fd   : Util.Systems.Os.File_Type;
      File : Util.Streams.Raw.Raw_Stream;
      P    : Interfaces.C.Strings.chars_ptr := Interfaces.C.Strings.New_String (Path);
   begin
      Fd := Util.Systems.Os.Sys_Open (Path  => P,
                                      Flags => O_RDONLY,
                                      Mode  => 0);
      Interfaces.C.Strings.Free (P);
      if Fd < 0 then
         AKT.Commands.Log.Error (-("Cannot read the editor's output"));
         raise Error;
      end if;
      File.Initialize (Fd);
      Context.Wallet.Set (Name, Keystore.T_STRING, File);
   end Import_Value;

   --  ------------------------------
   --  Get the editor command to launch.
   --  ------------------------------
   function Get_Editor (Command : in Command_Type) return String is
   begin
      if Command.Editor /= null and then Command.Editor'Length > 0 then
         return Command.Editor.all;
      end if;

      --  Use the $EDITOR if the environment variable defines it.
      if Ada.Environment_Variables.Exists ("EDITOR") then
         return Ada.Environment_Variables.Value ("EDITOR");
      end if;

      --  Use the editor which links to the default system-wide editor
      --  that can be configured on Ubuntu through /etc/alternatives.
      return "editor";
   end Get_Editor;

   --  ------------------------------
   --  Get the directory where the editor's file can be created.
   --  ------------------------------
   function Get_Directory (Command : in Command_Type;
                           Context : in out Context_Type) return String is
      pragma Unreferenced (Command, Context);

      Rand : Keystore.Random.Generator;
      Name : constant String := "akt-" & Rand.Generate (Bits => 32);
   begin
      return "/tmp/" & Name;
   end Get_Directory;

   procedure Make_Directory (Path : in String) is
      P      : Interfaces.C.Strings.chars_ptr;
      Result : Integer;
   begin
      Ada.Directories.Create_Path (Path);
      P := Interfaces.C.Strings.New_String (Path);
      Result := Util.Systems.Os.Sys_Chmod (P, 8#0700#);
      Interfaces.C.Strings.Free (P);
      if Result /= 0 then
         AKT.Commands.Log.Error (-("Cannot set the permission of {0}"), Path);
         raise Error;
      end if;
   end Make_Directory;

   --  ------------------------------
   --  Edit a value from the keystore by using an external editor.
   --  ------------------------------
   overriding
   procedure Execute (Command   : in out Command_Type;
                      Name      : in String;
                      Args      : in Argument_List'Class;
                      Context   : in out Context_Type) is
   begin
      if Args.Get_Count /= 1 then
         AKT.Commands.Usage (Args, Context, Name);

      else
         Context.Open_Keystore;
         declare
            Dir    : constant String := Command.Get_Directory (Context);
            Path   : constant String := Util.Files.Compose (Dir, "VALUE.txt");
            Editor : constant String := Command.Get_Editor;
            Proc   : Util.Processes.Process;

            procedure Cleanup;

            procedure Cleanup is
            begin
               if Ada.Directories.Exists (Path) then
                  Ada.Directories.Delete_File (Path);
               end if;
               if Ada.Directories.Exists (Dir) then
                  Ada.Directories.Delete_Tree (Dir);
               end if;
            end Cleanup;

         begin
            Make_Directory (Dir);
            Export_Value (Context, Args.Get_Argument (1), Path);
            Util.Processes.Spawn (Proc, Editor & " " & Path);
            Util.Processes.Wait (Proc);
            if Util.Processes.Get_Exit_Status (Proc) /= 0 then
               AKT.Commands.Log.Error (-("Editor exited with status{0}"),
                                       Natural'Image (Util.Processes.Get_Exit_Status (Proc)));
               Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
            else
               Import_Value (Context, Args.Get_Argument (1), Path);
            end if;
            Cleanup;

         exception
            when others =>
               Cleanup;
               raise;

         end;
      end if;
   end Execute;

   --  ------------------------------
   --  Setup the command before parsing the arguments and executing it.
   --  ------------------------------
   procedure Setup (Command : in out Command_Type;
                    Config  : in out GNAT.Command_Line.Command_Line_Configuration;
                    Context : in out Context_Type) is
      package GC renames GNAT.Command_Line;
   begin
      Setup (Config, Context);
      GC.Define_Switch (Config, Command.Editor'Access,
                        "-e:", "--editor=", -("Define the editor command to use"));
   end Setup;

end AKT.Commands.Edit;
