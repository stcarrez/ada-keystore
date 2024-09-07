-----------------------------------------------------------------------
--  akt-commands-config -- Config command to configure akt
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with AKT.Configs;
package body AKT.Commands.Config is

   --  ------------------------------
   --  Get a value from the keystore.
   --  ------------------------------
   overriding
   procedure Execute (Command   : in out Command_Type;
                      Name      : in String;
                      Args      : in Argument_List'Class;
                      Context   : in out Context_Type) is
      pragma Unreferenced (Command);
   begin
      if Args.Get_Count = 0 then
         AKT.Commands.Usage (Args, Context, Name);

      elsif Args.Get_Count = 2 then
         declare
            Name  : constant String := Args.Get_Argument (1);
            Value : constant String := Args.Get_Argument (2);
         begin
            AKT.Configs.Set (Name, Value);
         end;
         AKT.Configs.Save;
      end if;
   end Execute;

end AKT.Commands.Config;
