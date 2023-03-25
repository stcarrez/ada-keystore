-----------------------------------------------------------------------
--  akt-commands-otp -- One-time-password generation with otpauth
--  Copyright (C) 2023 Stephane Carrez
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
      Remove : aliased Boolean := False;
      Force  : aliased Boolean := False;
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

   --  Collect the list of OTP definitions in the keystore.
   procedure Collect_List (Context : in out Context_Type;
                           Into    : in out Util.Strings.Vectors.Vector);

end AKT.Commands.OTP;
