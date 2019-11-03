-----------------------------------------------------------------------
--  akt-commands-get -- Get content from keystore
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
with Ada.Command_Line;
with Ada.Streams.Stream_IO;
with Ada.Directories;
with Util.Streams.Raw;
with Util.Systems.Os;
with Util.Files;
with Util.Streams.Files;
with GNAT.Regpat;
with GNAT.Command_Line;
package body AKT.Commands.Get is

   use GNAT.Strings;

   procedure Extract (Wallet : in out Keystore.Wallet'Class;
                      Path   : in String;
                      Output : in String);

   Sep : Ada.Streams.Stream_Element_Array (1 .. Util.Systems.Os.Line_Separator'Length);
   for Sep'Address use Util.Systems.Os.Line_Separator'Address;

   Output : Util.Streams.Raw.Raw_Stream;

   procedure Extract (Wallet : in out Keystore.Wallet'Class;
                      Path   : in String;
                      Output : in String) is
      Pattern : constant GNAT.Regpat.Pattern_Matcher := GNAT.Regpat.Compile (Path & "/.*");
      List : Keystore.Entry_Map;
      Iter : Keystore.Entry_Cursor;
   begin
      Wallet.List (Pattern => Pattern,
                   Filter  => (Keystore.T_FILE => True, others => False),
                   Content => List);
      Iter := List.First;
      while Keystore.Entry_Maps.Has_Element (Iter) loop
         declare
            Name   : constant String := Keystore.Entry_Maps.Key (Iter);
            Target : constant String := Util.Files.Compose (Output, Name);
            Dir    : constant String := Ada.Directories.Containing_Directory (Target);
            File   : Util.Streams.Files.File_Stream;
         begin
            Ada.Text_IO.Put_Line ("Extract " & Name);
            Ada.Directories.Create_Path (Dir);

            File.Create (Mode => Ada.Streams.Stream_IO.Out_File,
                         Name => Target);
            Wallet.Get (Name   => Name,
                        Output => File);
         end;
         Keystore.Entry_Maps.Next (Iter);
      end loop;
   end Extract;

   --  ------------------------------
   --  Get a value from the keystore.
   --  ------------------------------
   overriding
   procedure Execute (Command   : in out Command_Type;
                      Name      : in String;
                      Args      : in Argument_List'Class;
                      Context   : in out Context_Type) is
   begin
      if Args.Get_Count = 0 then
         if Command.Dir /= null and Command.Dir'Length > 0 then
            Context.Open_Keystore (Use_Worker => True);
            Extract (Context.Wallet, Command.Dir.all, Command.Output.all);
         else
            AKT.Commands.Usage (Args, Context, Name);
         end if;
      else
         Context.Open_Keystore (Use_Worker => True);
         Output.Initialize (File => Util.Systems.Os.STDOUT_FILENO);
         for I in 1 .. Args.Get_Count loop
            declare
               Key : constant String := Args.Get_Argument (I);
            begin
               Context.Wallet.Get (Key, Output);
               if not Command.No_Newline then
                  Output.Write (Sep);
               end if;

            exception
               when Keystore.Not_Found =>
                  AKT.Commands.Log.Error (-("Value '{0}' not found"), Key);
                  Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);

            end;
         end loop;
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
      GC.Define_Switch (Config, Command.No_Newline'Access,
                        "-n", "", -("Do not output the trailing newline"));
      GC.Define_Switch (Config, Command.Dir'Access,
                        "-r:", "--recursive=", -("Extract the files recursively"));
      GC.Define_Switch (Config, Command.Output'Access,
                        "-o:", "--output=",
                        -("Store the result in the output file or directory"));
   end Setup;

end AKT.Commands.Get;
