-----------------------------------------------------------------------
--  akt-commands-password-set -- Change the wallet password
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
package body AKT.Commands.Password.Set is

   --  ------------------------------
   --  Change the wallet password.
   --  ------------------------------
   overriding
   procedure Execute (Command   : in out Command_Type;
                      Name      : in String;
                      Args      : in Argument_List'Class;
                      Context   : in out Context_Type) is
   begin
      Command.Mode := Keystore.KEY_REPLACE;
      AKT.Commands.Password.Execute (Password.Command_Type (Command), Name, Args, Context);
   end Execute;

end AKT.Commands.Password.Set;
