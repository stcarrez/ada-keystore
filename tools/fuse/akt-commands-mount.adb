-----------------------------------------------------------------------
--  akt-commands-mount -- Mount the keystore on the filesystem for direct access
--  Copyright (C) 2019, 2020, 2022 Stephane Carrez
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
with System;
with Fuse;
with AKT.Filesystem;
package body AKT.Commands.Mount is

   use type System.Address;

   function Sys_Daemon (No_Chdir : in Integer; No_Close : in Integer) return Integer
     with Import => True, Convention => C, Link_Name => "daemon";
   pragma Weak_External (Sys_Daemon);

   Mount_Command          : aliased Command_Type;

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
      Data.Direct_IO := not Command.Enable_Cache;

      --  We can open the keystore before going in background
      --  but don't create the worker tasks.
      Context.Open_Keystore (Args, Use_Worker => False);

      --  If daemon(3) is available and -d is defined, run it so that the parent
      --  process terminates and the child process continues.
      if not Command.Foreground and then Sys_Daemon'Address /= System.Null_Address then
         declare
            Result : constant Integer := Sys_Daemon (1, 0);
         begin
            if Result /= 0 then
               AKT.Commands.Log.Error (-("cannot run in background"));
            end if;
         end;
      end if;

      --  Now we can start the workers.
      if Context.Worker_Count > 1 then
         Context.Workers := new Keystore.Task_Manager (Context.Worker_Count);
         Keystore.Start (Context.Workers);
         Context.Wallet.Set_Work_Manager (Context.Workers);
      end if;

      --  Always run in foreground because Open_Keystore has started some tasks
      --  and we need them (they will dead in the child if fuse runs as daemon).
      Mount_Arguments.Append ("-f");

      if Command.Verbose_Fuse then
         Mount_Arguments.Append ("-d");
      end if;

      --  Enable big writes because it's faster with 128K writes.
      Mount_Arguments.Append ("-o");
      Mount_Arguments.Append ("big_writes");
      for I in Context.First_Arg .. Args.Get_Count loop
         Mount_Arguments.Append (Args.Get_Argument (I));
      end loop;

      AKT.Filesystem.Fuse_Keystore.Main (Mount_Arguments, Data);
   end Execute;

   --  ------------------------------
   --  Setup the command before parsing the arguments and executing it.
   --  ------------------------------
   overriding
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
                        Output => Command.Verbose_Fuse'Access,
                        Long_Switch => "--debug-fuse",
                        Help => -("Enable debug output of fuse library"));
      GC.Define_Switch (Config => Config,
                        Output => Command.Enable_Cache'Access,
                        Long_Switch => "--enable-cache",
                        Help => -("Allow the kernel to cache data from this file system"));
   end Setup;

   procedure Register (Driver : in out AKT.Commands.Drivers.Driver_Type) is
   begin
      Driver.Add_Command ("mount",
                          -("mount the keystore on the filesystem for a direct access"),
                          Mount_Command'Access);
   end Register;

end AKT.Commands.Mount;
