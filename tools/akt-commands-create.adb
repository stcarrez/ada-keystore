-----------------------------------------------------------------------
--  akt-commands-create -- Create a keystore
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
with Ada.Streams;
package body AKT.Commands.Create is

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

      Config       : Keystore.Wallet_Config := Keystore.Secure_Config;
   begin
      if Command.Counter_Range /= null and then Command.Counter_Range'Length > 0 then
         Parse_Range (Command.Counter_Range.all, Config);
      end if;
      Config.Overwrite := Command.Force;

      if Command.Gpg_User /= null and Command.Gpg_User'Length > 0 then

         Context.Set_GPG_User (Command.Gpg_User.all);
         Context.Create_GPG_Secret;

         Keystore.Files.Create (Container => Context.Wallet,
                                Password  => Context.Get_GPG_Secret,
                                Path      => Context.Wallet_File.all,
                                Config    => Config);

         Context.Save_GPG_Secret;

      else
         Keystore.Files.Create (Container => Context.Wallet,
                                Password  => Context.Provider.Get_Password,
                                Path      => Context.Wallet_File.all,
                                Config    => Config);
      end if;
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
                        Output => Command.Force'Access,
                        Switch => "-f",
                        Long_Switch => "--force",
                        Help   => "Force the creation of the keystore");
      GC.Define_Switch (Config => Config,
                        Output => Command.Gpg_User'Access,
                        Switch => "-g:",
                        Long_Switch => "--gpg=",
                        Argument => "USER",
                        Help   => "Use gpg to protect the keystore access");
   end Setup;

   --  ------------------------------
   --  Write the help associated with the command.
   --  ------------------------------
   overriding
   procedure Help (Command   : in out Command_Type;
                   Context   : in out Context_Type) is
      pragma Unreferenced (Command, Context);
   begin
      Ada.Text_IO.Put_Line ("akt create: create the keystore");
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("Usage: akt create [--counter-range min:max] [--force] [--gpg USER]");
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("  The create command is used to create the new keystore file.");
      Ada.Text_IO.Put_Line ("  By default the PBKDF2 iteration counter is in range"
                            & " 500000..1000000.");
      Ada.Text_IO.Put_Line ("  You can change this range by using the `--counter-range` option.");
      Ada.Text_IO.Put_Line ("  High values provide best password protection at the expense"
                            & " of speed.");
      Ada.Text_IO.Put_Line ("  When the `--gpg` option is used, the keystore is protected by");
      Ada.Text_IO.Put_Line ("  using gpg and one of the user's GPG key.");
   end Help;

end AKT.Commands.Create;
