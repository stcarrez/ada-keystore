-----------------------------------------------------------------------
--  akt-commands-mount -- Mount the keystore on the filesystem for direct access
--  Copyright (C) 2019, 2020 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with AKT.Commands.Drivers;
private package AKT.Commands.Mount is

   HAS_FUSE : constant Boolean := True;

   type Command_Type is new AKT.Commands.Drivers.Command_Type with private;

   --  Mount the keystore on the filesystem.
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

   procedure Register (Driver : in out AKT.Commands.Drivers.Driver_Type);

private

   type Command_Type is new AKT.Commands.Drivers.Command_Type with record
      Foreground   : aliased Boolean := False;
      Verbose_Fuse : aliased Boolean := False;
      Enable_Cache : aliased Boolean := False;
   end record;

end AKT.Commands.Mount;
