-----------------------------------------------------------------------
--  akt-commands-password-set -- Change the wallet password
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
package AKT.Commands.Password.Set is

   type Command_Type is new AKT.Commands.Password.Command_Type with private;

   --  Change the wallet password.
   overriding
   procedure Execute (Command   : in out Command_Type;
                      Name      : in String;
                      Args      : in Argument_List'Class;
                      Context   : in out Context_Type);

private

   type Command_Type is new AKT.Commands.Password.Command_Type with null record;

end AKT.Commands.Password.Set;
