-----------------------------------------------------------------------
--  akt-commands-get -- Get content from keystore
--  Copyright (C) 2019, 2021, 2022 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with Ada.Command_Line;
with Ada.Streams;
with Util.Systems.Os;
with Util.Streams.Raw;
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
         Context.Open_Keystore (Args, Use_Worker => True);
         Output.Initialize (File => Util.Systems.Os.STDOUT_FILENO);
         for I in Context.First_Arg .. Args.Get_Count loop
            declare
               Key : constant String := Args.Get_Argument (I);
            begin
               Context.Wallet.Get (Key, Output);
               if not Command.No_Newline then
                  Output.Write (Sep);
               end if;

            exception
               when Keystore.Not_Found =>
                  AKT.Commands.Log.Error (-("value '{0}' not found"), Key);
                  Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);

            end;
         end loop;
      end if;
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
      GC.Define_Switch (Config, Command.No_Newline'Access,
                        "-n", "", -("Do not output the trailing newline"));
   end Setup;

end AKT.Commands.Get;
