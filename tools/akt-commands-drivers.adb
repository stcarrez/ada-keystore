-----------------------------------------------------------------------
--  akt-commands-drivers -- Ada Keystore command driver
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
with Util.Files;
package body AKT.Commands.Drivers is

   --  ------------------------------
   --  Setup the command before parsing the arguments and executing it.
   --  ------------------------------
   overriding
   procedure Setup (Command : in out Command_Type;
                    Config  : in out GNAT.Command_Line.Command_Line_Configuration;
                    Context : in out Context_Type) is
   begin
      AKT.Commands.Setup (Config, Context);
   end Setup;

   --  ------------------------------
   --  Write the help associated with the command.
   --  ------------------------------
   overriding
   procedure Help (Command   : in out Command_Type;
                   Name      : in String;
                   Context   : in out Context_Type) is
      procedure Print_Help (Line : in String) is
      begin
         Ada.Text_IO.Put_Line (Line);
      end Print_Help;

   begin
      Util.Files.Read_File (Path    => "share/akt/resources/en/" & Name & ".txt",
                            Process => Print_Help'Access);
   end Help;

end AKT.Commands.Drivers;
