-----------------------------------------------------------------------
--  akt-commands-password -- Add/Change/Remove the wallet password
--  Copyright (C) 2019, 2022, 2024 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with Keystore.Passwords.Files;
with Keystore.Passwords.Unsafe;
with Keystore.Passwords.Input;
package body AKT.Commands.Password is

   package KP renames Keystore.Passwords;

   use GNAT.Strings;
   use type Keystore.Passwords.Provider_Access;
   use type Keystore.Header_Slot_Count_Type;

   --  ------------------------------
   --  Create the keystore file.
   --  ------------------------------
   overriding
   procedure Execute (Command   : in out Command_Type;
                      Name      : in String;
                      Args      : in Argument_List'Class;
                      Context   : in out Context_Type) is
      pragma Unreferenced (Name);

      Config : Keystore.Wallet_Config := Keystore.Secure_Config;
      New_Password_Provider : Keystore.Passwords.Provider_Access;
   begin
      Setup_Password_Provider (Context);
      Setup_Key_Provider (Context);
      if Command.Counter_Range /= null and then Command.Counter_Range'Length > 0 then
         Parse_Range (Command.Counter_Range.all, Config);
      end if;

      if Context.Info.Header_Count = 0 and then Context.Provider = null then
         Context.Provider := KP.Input.Create (-("Enter password: "), False);
      end if;
      if Command.Gpg_User'Length > 0 then
         declare
            GPG : Keystore.Passwords.GPG.Context_Type;
         begin
            AKT.Commands.Initialize (GPG);
            GPG.Create_Secret (Context.Key_Provider.all);
            Context.Change_Password (Args         => Args,
                                     New_Password => GPG,
                                     Config       => Config,
                                     Mode         => Command.Mode);
            GPG.Save_Secret (User   => Command.Gpg_User.all,
                             Index  => Context.Info.Header_Count + 1,
                             Wallet => Context.Wallet);
         end;
      else
         if Context.Provider = null then
            Context.Provider := KP.Input.Create (-("Enter password: "), False);
         end if;
         if Command.Password_File'Length > 0 then
            New_Password_Provider := KP.Files.Create (Command.Password_File.all);
         elsif Command.Unsafe_Password'Length > 0 then
            New_Password_Provider := KP.Unsafe.Create (Command.Unsafe_Password.all);
         else
            New_Password_Provider := KP.Input.Create (-("New password: "), False);
         end if;

         Context.Change_Password (Args         => Args,
                                  New_Password => New_Password_Provider.all,
                                  Config       => Config,
                                  Mode         => Command.Mode);
      end if;
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
      Setup (Config, Context);
      GC.Define_Switch (Config => Config,
                        Output => Command.Counter_Range'Access,
                        Switch => "-c:",
                        Long_Switch => "--counter-range:",
                        Argument => "RANGE",
                        Help => -("Set the range for the PBKDF2 counter"));
      GC.Define_Switch (Config => Config,
                        Output => Command.Password_File'Access,
                        Long_Switch => "--new-passfile=",
                        Argument => "PATH",
                        Help   => -("Read the file that contains the password"));
      GC.Define_Switch (Config => Config,
                        Output => Command.Unsafe_Password'Access,
                        Long_Switch => "--new-passfd=",
                        Argument => "NUM",
                        Help   => -("Read the password from the pipe with"
                          & " the given file descriptor"));
      GC.Define_Switch (Config => Config,
                        Output => Command.Unsafe_Password'Access,
                        Long_Switch => "--new-passsocket=",
                        Help   => -("The password is passed within the socket connection"));
      GC.Define_Switch (Config => Config,
                        Output => Command.Password_Env'Access,
                        Long_Switch => "--new-passenv=",
                        Argument => "NAME",
                        Help   => -("Read the environment variable that contains"
                        & " the password (not safe)"));
      GC.Define_Switch (Config => Config,
                        Output => Command.Unsafe_Password'Access,
                        Long_Switch => "--new-password=",
                        Help   => -("The password is passed within the command line (not safe)"));
      GC.Define_Switch (Config => Config,
                        Output => Command.Gpg_User'Access,
                        Switch => "-g:",
                        Long_Switch => "--gpg=",
                        Argument => "USER",
                        Help   => -("Use gpg to protect the keystore access"));
   end Setup;

end AKT.Commands.Password;
