-----------------------------------------------------------------------
--  akt-commands-extract -- Get content from keystore
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with AKT.Commands.Drivers;
private package AKT.Commands.Extract is

   type Command_Type is new AKT.Commands.Drivers.Command_Type with private;

   --  Get a value from the keystore.
   overriding
   procedure Execute (Command   : in out Command_Type;
                      Name      : in String;
                      Args      : in Argument_List'Class;
                      Context   : in out Context_Type);

   --  Setup the command before parsing the arguments and executing it.
   overriding
   procedure Setup (Command : in out Command_Type;
                    Config  : in out GNAT.Command_Line.Command_Line_Configuration;
                    Context : in out Context_Type);

private

   type Command_Type is new AKT.Commands.Drivers.Command_Type with record
      Output     : aliased GNAT.Strings.String_Access;
      Dir        : aliased GNAT.Strings.String_Access;
      Use_Stdout : aliased Boolean := False;
   end record;

end AKT.Commands.Extract;
