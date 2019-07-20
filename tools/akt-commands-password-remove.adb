-----------------------------------------------------------------------
--  akt-commands-password-remove -- Remove a wallet password
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
package body AKT.Commands.Password.Remove is

   --  ------------------------------
   --  Create the keystore file.
   --  ------------------------------
   overriding
   procedure Execute (Command   : in out Command_Type;
                      Name      : in String;
                      Args      : in Argument_List'Class;
                      Context   : in out Context_Type) is
      pragma Unreferenced (Name, Args);

      Empty : Keystore.Secret_Key (Length => 1);
   begin
      if Command.Force then
         Context.Change_Password (New_Password => Empty,
                                  Mode         => Keystore.KEY_REMOVE_LAST);
      else
         Context.Change_Password (New_Password => Empty,
                                  Mode         => Keystore.KEY_REMOVE);
      end if;
   end Execute;

   --  ------------------------------
   --  Setup the command before parsing the arguments and executing it.
   --  ------------------------------
   procedure Setup (Command : in out Command_Type;
                    Config  : in out GNAT.Command_Line.Command_Line_Configuration;
                    Context : in out Context_Type) is
      pragma Unreferenced (Context);

      package GC renames GNAT.Command_Line;
   begin
      GC.Define_Switch (Config => Config,
                        Output => Command.Force'Access,
                        Switch => "-f",
                        Long_Switch => "--force",
                        Help   => "Force erase of password");
   end Setup;

   --  ------------------------------
   --  Write the help associated with the command.
   --  ------------------------------
   overriding
   procedure Help (Command   : in out Command_Type;
                   Context   : in out Context_Type) is
      pragma Unreferenced (Command, Context);
   begin
      Ada.Text_IO.Put_Line ("akt password-clear: remove the password from the wallet key slots");
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("Usage: akt password-clear [--force]");
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("  Erase the password from the wallet master key slots.");
      Ada.Text_IO.Put_Line ("  Removing the last password makes the keystore unusable");
      Ada.Text_IO.Put_Line ("  and it is necessary to pass the --force option for that.");
   end Help;

end AKT.Commands.Password.Remove;
