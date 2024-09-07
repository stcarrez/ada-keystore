-----------------------------------------------------------------------
--  akt-commands-edit -- Edit content in keystore
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with AKT.Commands.Drivers;
private package AKT.Commands.Edit is

   type Command_Type is new AKT.Commands.Drivers.Command_Type with private;

   --  Get the editor command to launch.
   function Get_Editor (Command : in Command_Type) return String;

   --  Get the directory where the editor's file can be created.
   function Get_Directory (Command : in Command_Type;
                           Context : in out Context_Type) return String;

   --  Edit a value from the keystore by using an external editor.
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
      Editor : aliased GNAT.Strings.String_Access;
   end record;

end AKT.Commands.Edit;
