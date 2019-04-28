-----------------------------------------------------------------------
--  akt-commands-set -- Set content in keystore
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
with Util.Files;
package body AKT.Commands.Set is

   use GNAT.Strings;

   --  ------------------------------
   --  Insert a new value in the keystore.
   --  ------------------------------
   overriding
   procedure Execute (Command   : in out Command_Type;
                      Name      : in String;
                      Args      : in Argument_List'Class;
                      Context   : in out Context_Type) is
      pragma Unreferenced (Command, Name);
   begin
      if Command.File /= null and then Command.File'Length > 0 then
         if Args.Get_Count /= 1 then
            AKT.Commands.Usage (Context);
         else
            declare
               Content : Ada.Strings.Unbounded.Unbounded_String;
            begin
               Util.Files.Read_File (Command.File.all, Content);
               Context.Open_Keystore;
               Context.Wallet.Set (Name => Args.Get_Argument (1),
                                   Content => Ada.Strings.Unbounded.To_String (Content));

            end;
         end if;

      elsif Args.Get_Count /= 2 then
         AKT.Commands.Usage (Context);

      else
         Context.Open_Keystore;
         Context.Wallet.Set (Name    => Args.Get_Argument (1),
                             Content => Args.Get_Argument (2));
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
      GC.Define_Switch (Config, Command.File'Access,
                        "-f:", "--file=", "Define the path of the file to read");
   end Setup;

   --  ------------------------------
   --  Write the help associated with the command.
   --  ------------------------------
   overriding
   procedure Help (Command   : in out Command_Type;
                   Context   : in out Context_Type) is
      pragma Unreferenced (Command);
   begin
      AKT.Commands.Usage (Context);
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("set: insert a new value in the keystore");
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("Usage: set <name> <value>");
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("  ");
   end Help;

end AKT.Commands.Set;
