-----------------------------------------------------------------------
--  akt-commands-otp -- One-time-password generation with otpauth
--  Copyright (C) 2023 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with AKT.Commands.Drivers;
private with Util.Strings.Vectors;
private package AKT.Commands.OTP is

   type Command_Type is new AKT.Commands.Drivers.Command_Type with private;

   --  Store the otpauth secret or generate the OTP code.
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
      Remove      : aliased Boolean := False;
      Force       : aliased Boolean := False;
      Interactive : aliased Boolean := False;
   end record;

   --  Register or update an otpauth URI.
   procedure Register (Command : in out Command_Type;
                       URI     : in String;
                       Context : in out Context_Type);

   --  Generate to OTP code for the selected account.
   procedure Generate (Command : in out Command_Type;
                       Account : in String;
                       Context : in out Context_Type);

   --  List the OTP authorizations that are registered.
   procedure List (Command   : in out Command_Type;
                   Context   : in out Context_Type);

   procedure Interactive (Command : in out Command_Type;
                          Context : in out Context_Type);

   --  Collect the list of OTP definitions in the keystore.
   procedure Collect_List (Context : in out Context_Type;
                           Into    : in out Util.Strings.Vectors.Vector);

end AKT.Commands.OTP;
