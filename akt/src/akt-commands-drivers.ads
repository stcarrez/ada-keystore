-----------------------------------------------------------------------
--  akt-commands-drivers -- Ada Keystore command driver
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with Util.Commands.Drivers;
with Util.Commands.Parsers.GNAT_Parser;
with Util.Commands.Raw_IO;
private package AKT.Commands.Drivers is

   package Main_Driver is
     new Util.Commands.Drivers (Context_Type  => Context_Type,
                                Config_Parser => Util.Commands.Parsers.GNAT_Parser.Config_Parser,
                                Translate     => Intl.Gettext,
                                IO            => Util.Commands.Raw_IO,
                                Driver_Name   => "akt");

   subtype Help_Command_Type is Main_Driver.Help_Command_Type;
   subtype Driver_Type is Main_Driver.Driver_Type;

   type Command_Type is abstract new Main_Driver.Command_Type with null record;

   --  Setup the command before parsing the arguments and executing it.
   overriding
   procedure Setup (Command : in out Command_Type;
                    Config  : in out GNAT.Command_Line.Command_Line_Configuration;
                    Context : in out Context_Type);

   --  Write the help associated with the command.
   overriding
   procedure Help (Command   : in out Command_Type;
                   Name      : in String;
                   Context   : in out Context_Type);

end AKT.Commands.Drivers;
