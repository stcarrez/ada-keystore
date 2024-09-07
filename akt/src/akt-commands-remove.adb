-----------------------------------------------------------------------
--  akt-commands-remove -- Remove content from keystore
--  Copyright (C) 2019, 2023 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
package body AKT.Commands.Remove is

   --  ------------------------------
   --  Remove a value from the keystore.
   --  ------------------------------
   overriding
   procedure Execute (Command   : in out Command_Type;
                      Name      : in String;
                      Args      : in Argument_List'Class;
                      Context   : in out Context_Type) is
      pragma Unreferenced (Command);
   begin
      Context.Open_Keystore (Args);
      if Args.Get_Count < Context.First_Arg then
         AKT.Commands.Usage (Args, Context, Name,
                             -("missing value name to remove"));
      else
         for I in Context.First_Arg .. Args.Get_Count loop
            if Context.Wallet.Contains (Args.Get_Argument (I)) then
               Context.Wallet.Delete (Args.Get_Argument (I));
            end if;
         end loop;
      end if;
   end Execute;

end AKT.Commands.Remove;
