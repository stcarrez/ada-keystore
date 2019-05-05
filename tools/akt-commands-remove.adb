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
with Ada.Text_IO;
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

   --  ------------------------------
   --  Write the help associated with the command.
   --  ------------------------------
   overriding
   procedure Help (Command   : in out Command_Type;
                   Context   : in out Context_Type) is
      pragma Unreferenced (Command);
   begin
      --  AKT.Commands.Usage (Context);
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("akt remove: remove values from the keystore");
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("Usage: akt remove <name> [...]");
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("  The remove command is used to erase a content from the wallet.");
      Ada.Text_IO.Put_Line ("  The data blocks that contained the content are cleared.");
      Ada.Text_IO.Put_Line ("  The secure keys that protect the content are also cleared.");
      Ada.Text_IO.Put_Line ("  You can erase several values at the same time.");
   end Help;

end AKT.Commands.Remove;
