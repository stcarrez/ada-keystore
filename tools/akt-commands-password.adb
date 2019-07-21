-----------------------------------------------------------------------
--  akt-commands-password -- Add/Change/Remove the wallet password
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
with AKT.Passwords.Files;
with AKT.Passwords.Unsafe;
with AKT.Passwords.Input;
package body AKT.Commands.Password is

   use GNAT.Strings;

   --  ------------------------------
   --  Create the keystore file.
   --  ------------------------------
   overriding
   procedure Execute (Command   : in out Command_Type;
                      Name      : in String;
                      Args      : in Argument_List'Class;
                      Context   : in out Context_Type) is
      pragma Unreferenced (Name, Args);

      Config : Keystore.Wallet_Config := Keystore.Secure_Config;
      New_Password_Provider : AKT.Passwords.Provider_Access;
   begin
      if Command.Counter_Range /= null and then Command.Counter_Range'Length > 0 then
         Parse_Range (Command.Counter_Range.all, Config);
      end if;
      if Command.Password_File'Length > 0 then
         New_Password_Provider := Passwords.Files.Create (Command.Password_File.all);
      elsif Context.Unsafe_Password'Length > 0 then
         New_Password_Provider := Passwords.Unsafe.Create (Command.Unsafe_Password.all);
      else
         New_Password_Provider := AKT.Passwords.Input.Create (False);
      end if;

      Context.Change_Password (New_Password => New_Password_Provider.Get_Password,
                               Config       => Config,
                               Mode         => Command.Mode);
   end Execute;

   --  ------------------------------
   --  Setup the command before parsing the arguments and executing it.
   --  ------------------------------
   procedure Setup (Command : in out Command_Type;
                    Config  : in out GNAT.Command_Line.Command_Line_Configuration;
                    Context : in out Context_Type) is
      pragma Unreferenced (Context);

      package GC renames GNAT.Command_Line;
   begin
      GC.Define_Switch (Config => Config,
                        Output => Command.Counter_Range'Access,
                        Switch => "-c:",
                        Long_Switch => "--counter-range:",
                        Argument => "RANGE",
                        Help => "Set the range for the PBKDF2 counter");
      GC.Define_Switch (Config => Config,
                        Output => Command.Password_File'Access,
                        Long_Switch => "--new-passfile=",
                        Argument => "PATH",
                        Help   => "Read the file that contains the password");
      GC.Define_Switch (Config => Config,
                        Output => Command.Unsafe_Password'Access,
                        Long_Switch => "--new-passfd=",
                        Argument => "NUM",
                        Help   => "Read the password from the pipe with"
                          & " the given file descriptor");
      GC.Define_Switch (Config => Config,
                        Output => Command.Unsafe_Password'Access,
                        Long_Switch => "--new-passsocket=",
                        Help   => "The password is passed within the socket connection");
      GC.Define_Switch (Config => Config,
                        Output => Command.Password_Env'Access,
                        Long_Switch => "--new-passenv=",
                        Argument => "NAME",
                        Help   => "Read the environment variable that contains"
                        & " the password (not safe)");
      GC.Define_Switch (Config => Config,
                        Output => Command.Unsafe_Password'Access,
                        Switch => "-p:",
                        Long_Switch => "--new-password=",
                        Help   => "The password is passed within the command line (not safe)");
   end Setup;

end AKT.Commands.Password;
