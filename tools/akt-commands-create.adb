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
with Keystore.Passwords.Files;
package body AKT.Commands.Create is

   use GNAT.Strings;
   use type Keystore.Passwords.Keys.Key_Provider_Access;

   --  ------------------------------
   --  Create the keystore file.
   --  ------------------------------
   overriding
   procedure Execute (Command   : in out Command_Type;
                      Name      : in String;
                      Args      : in Argument_List'Class;
                      Context   : in out Context_Type) is
      pragma Unreferenced (Name);

      Config  : Keystore.Wallet_Config := Keystore.Secure_Config;
      Path    : constant String := Context.Get_Keystore_Path (Args);
   begin
      Setup_Password_Provider (Context);

      if Command.Counter_Range /= null and then Command.Counter_Range'Length > 0 then
         Parse_Range (Command.Counter_Range.all, Config);
      end if;
      Config.Overwrite := Command.Force;

      if Command.Storage_Count /= null and then Command.Storage_Count'Length > 0 then
         begin
            Config.Storage_Count := Positive'Value (Command.Storage_Count.all);

         exception
            when others =>
               AKT.Commands.Log.Error (-("Split counter is invalid or out of range: {0}"),
                                       Command.Storage_Count.all);
               raise Error;
         end;
      end if;
      if Context.Data_Path'Length > 0 and Config.Storage_Count = 1 then
         Config.Storage_Count := 10;
      end if;

      if Command.Gpg_Mode then

         Context.GPG.Create_Secret;
         Context.Wallet.Set_Master_Key (Context.GPG);

         Context.Wallet.Create (Password  => Context.GPG,
                                Path      => Path,
                                Data_Path => Context.Data_Path.all,
                                Config    => Config);
         Context.GPG.Save_Secret (Args.Get_Argument (Context.First_Arg), 1, Context.Wallet);

         for I in Context.First_Arg + 1 .. Args.Get_Count loop
            declare
               GPG2 : Keystore.Passwords.GPG.Context_Type;
            begin
               AKT.Commands.Initialize (GPG2);
               GPG2.Create_Secret;
               Context.Wallet.Set_Key (Context.GPG, GPG2, Config, Keystore.KEY_ADD);
               GPG2.Save_Secret (Args.Get_Argument (I), Keystore.Header_Slot_Index_Type (I),
                                 Context.Wallet);
            end;
         end loop;

      else
         if Context.Wallet_Key_File'Length > 0 then
            Context.Key_Provider
              := Keystore.Passwords.Files.Generate (Context.Wallet_Key_File.all);
         end if;
         if Context.Key_Provider /= null then
            Context.Wallet.Set_Master_Key (Context.Key_Provider.all);
         end if;
         Keystore.Files.Create (Container => Context.Wallet,
                                Password  => Context.Provider.all,
                                Path      => Path,
                                Data_Path => Context.Data_Path.all,
                                Config    => Config);
      end if;
   end Execute;

   --  ------------------------------
   --  Setup the command before parsing the arguments and executing it.
   --  ------------------------------
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
                        Output => Command.Storage_Count'Access,
                        Switch => "-S:",
                        Long_Switch => "--split:",
                        Argument => "COUNT",
                        Help => -("Split the data blocks in COUNT separate files"));
      GC.Define_Switch (Config => Config,
                        Output => Command.Force'Access,
                        Switch => "-f",
                        Long_Switch => "--force",
                        Help   => -("Force the creation of the keystore"));
      GC.Define_Switch (Config => Config,
                        Output => Command.Gpg_Mode'Access,
                        Switch => "-g",
                        Long_Switch => "--gpg",
                        Help   => -("Use gpg to protect the keystore access"));
   end Setup;

end AKT.Commands.Create;
