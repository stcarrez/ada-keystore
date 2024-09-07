-----------------------------------------------------------------------
--  akt-commands-create -- Create a keystore
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with AKT.Commands.Drivers;
private package AKT.Commands.Create is

   type Command_Type is new AKT.Commands.Drivers.Command_Type with private;

   --  Create the keystore file.
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
      Force         : aliased Boolean := False;
      Counter_Range : aliased GNAT.Strings.String_Access;
      Storage_Count : aliased GNAT.Strings.String_Access;
      Gpg_Mode      : aliased Boolean := False;
   end record;

end AKT.Commands.Create;
