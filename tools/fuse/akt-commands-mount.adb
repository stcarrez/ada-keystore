-----------------------------------------------------------------------
--  akt-commands-mount -- Mount the keystore on the filesystem for direct access
--  Copyright (C) 2019, 2020 Stephane Carrez
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
with Fuse;
with AKT.Filesystem;
package body AKT.Commands.Mount is

   --  ------------------------------
   --  Mount the keystore on the filesystem.
   --  ------------------------------
   overriding
   procedure Execute (Command   : in out Command_Type;
                      Name      : in String;
                      Args      : in Argument_List'Class;
                      Context   : in out Context_Type) is
      pragma Unreferenced (Name);

      Data : AKT.Filesystem.User_Data_Type;
      Mount_Arguments : Fuse.Arguments_Type;
   begin
      Data.Wallet := Context.Wallet'Unchecked_Access;

      Context.Open_Keystore (Args, Use_Worker => True);

      if Command.Foreground then
         Mount_Arguments.Append ("-f");
      end if;
      if Command.Verbose_Fuse then
         Mount_Arguments.Append ("-d");
      end if;
      for I in Context.First_Arg .. Args.Get_Count loop
         Mount_Arguments.Append (Args.Get_Argument (I));
      end loop;

      AKT.Filesystem.Fuse_Keystore.Main (Mount_Arguments, Data);
   end Execute;

   --  ------------------------------
   --  Setup the command before parsing the arguments and executing it.
   --  ------------------------------
   procedure Setup (Command : in out Command_Type;
                    Config  : in out GNAT.Command_Line.Command_Line_Configuration;
                    Context : in out Context_Type) is
      package GC renames GNAT.Command_Line;
   begin
      Drivers.Command_Type (Command).Setup (Config, Context);
      GC.Define_Switch (Config => Config,
                        Output => Command.Foreground'Access,
                        Switch => "-f",
                        Long_Switch => "--foreground",
                        Help => -("Run as foreground (no daemonize)"));
      GC.Define_Switch (Config => Config,
                        Output => Command.Foreground'Access,
                        Long_Switch => "--debug-fuse",
                        Help => -("Enable debug output of fuse library"));
   end Setup;

end AKT.Commands.Mount;
