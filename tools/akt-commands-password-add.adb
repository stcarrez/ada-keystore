-----------------------------------------------------------------------
--  akt-commands-password-add -- Add a wallet password
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
package body AKT.Commands.Password.Add is

   --  ------------------------------
   --  Add a password to the wallet.
   --  ------------------------------
   overriding
   procedure Execute (Command   : in out Command_Type;
                      Name      : in String;
                      Args      : in Argument_List'Class;
                      Context   : in out Context_Type) is
   begin
      Command.Mode := Keystore.KEY_ADD;
      AKT.Commands.Password.Execute (Password.Command_Type (Command), Name, Args, Context);
   end Execute;

   --  ------------------------------
   --  Write the help associated with the command.
   --  ------------------------------
   overriding
   procedure Help (Command   : in out Command_Type;
                   Context   : in out Context_Type) is
      pragma Unreferenced (Command, Context);
   begin
      Ada.Text_IO.Put_Line ("akt password-add: add a new password to protect the wallet");
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("Usage: akt password-add [--passfile=PATH] [--password=ARG] "
                           & "[--passenv=NAME]");
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("  Add a new password to protect the wallet.");
      Ada.Text_IO.Put_Line ("  The password is added in a free key slot if there is one.");
   end Help;

end AKT.Commands.Password.Add;
