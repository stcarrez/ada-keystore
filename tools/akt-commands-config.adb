-----------------------------------------------------------------------
--  akt-commands-config -- Config command to configure akt
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
with AKT.Configs;
package body AKT.Commands.Config is

   use GNAT.Strings;

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
         AKT.Commands.Usage (Args, Context, Name);

      elsif Args.Get_Count = 2 then
         declare
            Name  : constant String := Args.Get_Argument (1);
            Value : constant String := Args.Get_Argument (2);
         begin
            AKT.Configs.Set (Name, Value);
         end;
         AKT.Configs.Save;
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
      Drivers.Command_Type (Command).Setup (Config, Context);
      GC.Define_Switch (Config, Command.No_Newline'Access,
                        "-n", "", -("Do not output the trailing newline"));
      GC.Define_Switch (Config, Command.Dir'Access,
                        "-r:", "--recursive=", -("Extract the files recursively"));
      GC.Define_Switch (Config, Command.Output'Access,
                        "-o:", "--output=",
                        -("Store the result in the output file or directory"));
   end Setup;

end AKT.Commands.Config;
