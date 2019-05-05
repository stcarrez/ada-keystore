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
with Util.Streams.Raw;
with Util.Systems.Os;
with GNAT.Command_Line;
package body AKT.Commands.Get is

   Sep : Ada.Streams.Stream_Element_Array (1 .. Util.Systems.Os.Line_Separator'Length);
   for Sep'Address use Util.Systems.Os.Line_Separator'Address;

   --  ------------------------------
   --  Get a value from the keystore.
   --  ------------------------------
   overriding
   procedure Execute (Command   : in out Command_Type;
                      Name      : in String;
                      Args      : in Argument_List'Class;
                      Context   : in out Context_Type) is
      Output : Util.Streams.Raw.Raw_Stream;
   begin
      if Args.Get_Count = 0 then
         AKT.Commands.Usage (Args, Context, Name);
      else
         Context.Open_Keystore;
         Output.Initialize (File => Util.Systems.Os.STDOUT_FILENO);
         for I in 1 .. Args.Get_Count loop
            Context.Wallet.Write (Args.Get_Argument (I), Output);
            if not Command.No_Newline then
               Output.Write (Sep);
            end if;
         end loop;
      end if;

   exception
      when Keystore.Not_Found =>
         null;
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
      pragma Unreferenced (Command);
   begin
      --  AKT.Commands.Usage (Context);
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("akt get: get a value from the keystore");
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("Usage: get <name>");
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("  ");
   end Help;

end AKT.Commands.Get;
