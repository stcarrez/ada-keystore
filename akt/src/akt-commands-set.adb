-----------------------------------------------------------------------
--  akt-commands-set -- Set content in keystore
--  Copyright (C) 2019, 2023 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

package body AKT.Commands.Set is

   --  ------------------------------
   --  Insert a new value in the keystore.
   --  ------------------------------
   overriding
   procedure Execute (Command   : in out Command_Type;
                      Name      : in String;
                      Args      : in Argument_List'Class;
                      Context   : in out Context_Type) is
      pragma Unreferenced (Command);
   begin
      --  Open keystore without use workers because we expect small data.
      Context.Open_Keystore (Args, Use_Worker => False);
      if Args.Get_Count /= Context.First_Arg + 1 then
         AKT.Commands.Usage (Args, Context, Name,
                             -("missing name and value to set"));

      else
         Context.Wallet.Set (Name    => Args.Get_Argument (Context.First_Arg),
                             Content => Args.Get_Argument (Context.First_Arg + 1));
      end if;
   end Execute;

end AKT.Commands.Set;
