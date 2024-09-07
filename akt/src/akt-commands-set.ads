-----------------------------------------------------------------------
--  akt-commands-set -- Set content in keystore
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with AKT.Commands.Drivers;
private package AKT.Commands.Set is

   type Command_Type is new AKT.Commands.Drivers.Command_Type with null record;

   --  Insert a new value in the keystore.
   overriding
   procedure Execute (Command   : in out Command_Type;
                      Name      : in String;
                      Args      : in Argument_List'Class;
                      Context   : in out Context_Type);

end AKT.Commands.Set;
