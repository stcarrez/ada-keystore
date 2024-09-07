-----------------------------------------------------------------------
--  akt-commands-password -- Add/Change/Remove the wallet password
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with AKT.Commands.Drivers;
with Keystore;
private package AKT.Commands.Password is

   type Command_Type is abstract new AKT.Commands.Drivers.Command_Type with private;

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

   type Command_Type is abstract new AKT.Commands.Drivers.Command_Type with record
      Mode              : Keystore.Mode_Type := Keystore.KEY_ADD;
      Counter_Range     : aliased GNAT.Strings.String_Access;
      Password_File     : aliased GNAT.Strings.String_Access;
      Password_Env      : aliased GNAT.Strings.String_Access;
      Unsafe_Password   : aliased GNAT.Strings.String_Access;
      Gpg_User          : aliased GNAT.Strings.String_Access;
   end record;

end AKT.Commands.Password;
