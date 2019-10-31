-----------------------------------------------------------------------
--  akt-commands-remove -- Remove content from keystore
--  Copyright (C) 2019 Stephane Carrez
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
      if Args.Get_Count = 0 then
         AKT.Commands.Usage (Args, Context, Name);
      else
         Context.Open_Keystore;
         for I in 1 .. Args.Get_Count loop
            if Context.Wallet.Contains (Args.Get_Argument (I)) then
               Context.Wallet.Delete (Args.Get_Argument (I));
            end if;
         end loop;
      end if;
   end Execute;

end AKT.Commands.Remove;
