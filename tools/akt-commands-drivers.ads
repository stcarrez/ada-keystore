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
with Util.Commands.Drivers;
with Util.Commands.Parsers.GNAT_Parser;
with Util.Commands.Raw_IO;
private package AKT.Commands.Drivers is

   package Main_Driver is
     new Util.Commands.Drivers (Context_Type  => Context_Type,
                                Config_Parser => Util.Commands.Parsers.GNAT_Parser.Config_Parser,
                                Translate     => Intl.Gettext,
                                IO            => Util.Commands.Raw_IO,
                                Driver_Name   => "akt");

   subtype Help_Command_Type is Main_Driver.Help_Command_Type;
   subtype Driver_Type is Main_Driver.Driver_Type;

   type Command_Type is abstract new Main_Driver.Command_Type with null record;

   --  Setup the command before parsing the arguments and executing it.
   overriding
   procedure Setup (Command : in out Command_Type;
                    Config  : in out GNAT.Command_Line.Command_Line_Configuration;
                    Context : in out Context_Type);

   --  Write the help associated with the command.
   overriding
   procedure Help (Command   : in out Command_Type;
                   Name      : in String;
                   Context   : in out Context_Type);

end AKT.Commands.Drivers;
