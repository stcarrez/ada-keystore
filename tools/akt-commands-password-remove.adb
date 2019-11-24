-----------------------------------------------------------------------
--  akt-commands-password-remove -- Remove a wallet password
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
package body AKT.Commands.Password.Remove is

   use type Keystore.Header_Slot_Count_Type;

   function Get_Slot (Value : in String) return Keystore.Key_Slot;

   function Get_Slot (Value : in String) return Keystore.Key_Slot is
   begin
      if Value = "" then
         AKT.Commands.Log.Error (-("Missing --slot SLOT option to indicate "
                                 & "the key slot to erase"));
         raise Error;
      end if;
      begin
         return Keystore.Key_Slot'Value (Value);

      exception
         when others =>
            AKT.Commands.Log.Error (-("Invalid key slot number. "
                                    & "It must be a number in range 1..7."));
            raise Error;
      end;
   end Get_Slot;

   --  ------------------------------
   --  Remove the wallet password.
   --  ------------------------------
   overriding
   procedure Execute (Command   : in out Command_Type;
                      Name      : in String;
                      Args      : in Argument_List'Class;
                      Context   : in out Context_Type) is
      pragma Unreferenced (Name);

      Path  : constant String := Context.Get_Keystore_Path (Args);
      Slot  : constant Keystore.Key_Slot := Get_Slot (Command.Slot.all);
   begin
      Setup_Password_Provider (Context);

      Context.Wallet.Open (Path => Path,
                           Info => Context.Info);

      if not Context.No_Password_Opt or else Context.Info.Header_Count = 0 then
         Context.Wallet.Unlock (Context.Provider.all, Context.Slot);

         Context.Wallet.Remove_Key (Password => Context.Provider.all,
                                    Slot     => Slot,
                                    Force    => Command.Force);
      else
         Context.GPG.Load_Secrets (Context.Wallet);
         Context.Wallet.Unlock (Context.GPG, Context.Slot);
         Context.Wallet.Remove_Key (Password => Context.GPG,
                                    Slot     => Slot,
                                    Force    => Command.Force);
      end if;

      Ada.Text_IO.Put_Line (-("The password was successfully removed."));

   exception
      when Keystore.Used_Key_Slot =>
         AKT.Commands.Log.Error (-("Refusing to erase the key slot used by current password."));
         AKT.Commands.Log.Error (-("Use the --force option if you really want "
                                 & "to erase this slot."));
         raise Error;

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
                        Output => Command.Force'Access,
                        Switch => "-f",
                        Long_Switch => "--force",
                        Help   => -("Force erase of password used to unlock the keystore"));
      GC.Define_Switch (Config => Config,
                        Output => Command.Slot'Access,
                        Switch => "-s:",
                        Long_Switch => "--slot:",
                        Argument => "SLOT",
                        Help   => -("Defines the key slot to erase (1..7)"));
   end Setup;

end AKT.Commands.Password.Remove;
