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
with Util.Streams.Raw;
with Util.Systems.Os;
with GNAT.Command_Line;
package body AKT.Commands.Get is

   Sep : Ada.Streams.Stream_Element_Array (1 .. Util.Systems.Os.Line_Separator'Length);
   for Sep'Address use Util.Systems.Os.Line_Separator'Address;

   Output : Util.Streams.Raw.Raw_Stream;

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
      else
         Context.Open_Keystore;
         Output.Initialize (File => Util.Systems.Os.STDOUT_FILENO);
         for I in 1 .. Args.Get_Count loop
            declare
               Key : constant String := Args.Get_Argument (I);
            begin
               Context.Wallet.Write (Key, Output);
               if not Command.No_Newline then
                  Output.Write (Sep);
               end if;

            exception
               when Keystore.Not_Found =>
                  AKT.Commands.Log.Error ("Value '{0}' not found", Key);
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
      pragma Unreferenced (Context);

      package GC renames GNAT.Command_Line;
   begin
      GC.Define_Switch (Config, Command.No_Newline'Access,
                        "-n", "", "Do not output the trailing newline");
   end Setup;

   --  ------------------------------
   --  Write the help associated with the command.
   --  ------------------------------
   overriding
   procedure Help (Command   : in out Command_Type;
                   Context   : in out Context_Type) is
      pragma Unreferenced (Command, Context);
   begin
      Ada.Text_IO.Put_Line ("akt get: get a value from the keystore");
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("Usage: get [-n] <name> [...]");
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("  The get command allows to retrieve the value associated with a");
      Ada.Text_IO.Put_Line ("  wallet entry. It retrieves the value for each name passed");
      Ada.Text_IO.Put_Line ("  to the command. By default a newline is emitted after each value.");
      Ada.Text_IO.Put_Line ("  The '-n' option prevents the output of the trailing newline.");
   end Help;

end AKT.Commands.Get;
