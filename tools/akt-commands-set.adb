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
with Ada.Streams.Stream_IO;
with Util.Streams.Files;
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
   begin
      if Command.File /= null and then Command.File'Length > 0 then
         if Args.Get_Count /= 1 then
            AKT.Commands.Usage (Args, Context, Name);
         else
            declare
               File    : Util.Streams.Files.File_Stream;
            begin
               File.Open (Mode => Ada.Streams.Stream_IO.In_File,
                          Name => Command.File.all);
               --  Open keystore with workers because we expect possibly big data.
               Context.Open_Keystore (Use_Worker => True);
               Context.Wallet.Set (Name  => Args.Get_Argument (1),
                                   Kind  => Keystore.T_STRING,
                                   Input => File);

            end;
         end if;

      elsif Args.Get_Count /= 2 then
         AKT.Commands.Usage (Args, Context, Name);

      else
         --  Open keystore without use workers because we expect small data.
         Context.Open_Keystore (Use_Worker => False);
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
      pragma Unreferenced (Context);

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
      pragma Unreferenced (Command, Context);
   begin
      Ada.Text_IO.Put_Line ("set: insert or update a value in the keystore");
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("Usage: akt set <name> [<value> | -f <file>]");
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("  The set command is used to store a content in the wallet.");
      Ada.Text_IO.Put_Line ("  The content is either passed as argument or read from a file.");
      Ada.Text_IO.Put_Line ("  If the wallet already contains the name, the value is updated.");
   end Help;

end AKT.Commands.Set;
