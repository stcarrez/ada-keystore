-----------------------------------------------------------------------
--  akt-commands-genkey -- Generate simple keys to lock/unkock wallets
--  Copyright (C) 2023 Stephane Carrez
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
with GNAT.Command_Line;
with AKT.Configs;
with Keystore.Passwords.Files;
package body AKT.Commands.Genkey is

   --  ------------------------------
   --  Generate or list some simple keys.
   --  ------------------------------
   overriding
   procedure Execute (Command   : in out Command_Type;
                      Name      : in String;
                      Args      : in Argument_List'Class;
                      Context   : in out Context_Type) is
      Dir : constant String := AKT.Configs.Get_Directory_Key_Path;
   begin
      if Dir'Length = 0 then
         AKT.Commands.Log.Error (-("no valid directory keys can be created"));
         raise Error;
      end if;
      for I in 1 .. Args.Get_Count loop
         declare
            Key_Name : constant String := Args.Get_Argument (I);
            Path     : constant String := Get_Named_Key_Path (Context, Key_Name);
         begin
            if Ada.Directories.Exists (Path) then
               if Command.Remove then
                  Ada.Directories.Delete_File (Path);
               else
                  AKT.Commands.Log.Error (-("key '{0}' is already defined"), Key_Name);
                  raise Error;
               end if;
            elsif not Command.Remove then
               Context.Key_Provider := Keystore.Passwords.Files.Generate (Path);
            end if;
         end;
      end loop;
   end Execute;

   --  ------------------------------
   --  Setup the command before parsing the arguments and executing it.
   --  ------------------------------
   overriding
   procedure Setup (Command : in out Command_Type;
                    Config  : in out GNAT.Command_Line.Command_Line_Configuration;
                    Context : in out Context_Type) is
      package GC renames GNAT.Command_Line;
   begin
      Drivers.Command_Type (Command).Setup (Config, Context);
      GC.Define_Switch (Config, Command.Remove'Access,
                        "-r", "--remove", -("Remove the named key"));
   end Setup;

end AKT.Commands.Genkey;
