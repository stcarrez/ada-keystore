-----------------------------------------------------------------------
--  akt-commands-info -- Info command of keystore
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
with Ada.Calendar.Formatting;
with Keystore.Verifier;
package body AKT.Commands.Info is

   --  ------------------------------
   --  List the value entries of the keystore.
   --  ------------------------------
   overriding
   procedure Execute (Command   : in out Command_Type;
                      Name      : in String;
                      Args      : in Argument_List'Class;
                      Context   : in out Context_Type) is
      pragma Unreferenced (Command, Name, Args);

      Path : constant String := Context.Get_Keystore_Path;
   begin
      Keystore.Verifier.Print_Information (Path);
   end Execute;

   --  ------------------------------
   --  Write the help associated with the command.
   --  ------------------------------
   overriding
   procedure Help (Command   : in out Command_Type;
                   Context   : in out Context_Type) is
      pragma Unreferenced (Command, Context);
   begin
      Ada.Text_IO.Put_Line ("list: list values of the keystore");
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("Usage: akt list");
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("  List the values stored in the keystore with their name,");
      Ada.Text_IO.Put_Line ("  size, type and creation date.");
   end Help;

end AKT.Commands.Info;