-----------------------------------------------------------------------
--  akt-commands-password-remove -- Remove a wallet password
--  Copyright (C) 2019, 2021, 2022, 2023 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
package body AKT.Commands.Password.Remove is

   use type Keystore.Header_Slot_Count_Type;
   use type Keystore.Passwords.Keys.Key_Provider_Access;

   function Get_Slot (Value : in String) return Keystore.Key_Slot;

   function Get_Slot (Value : in String) return Keystore.Key_Slot is
   begin
      return Keystore.Key_Slot'Value (Value);

   exception
      when others =>
         AKT.Commands.Log.Error (-("invalid key slot number: "
                                     & "it must be a number in range 1..7"));
         raise Error;
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
      Slot  : Keystore.Key_Slot;
   begin
      Setup_Password_Provider (Context);
      Setup_Key_Provider (Context);

      Context.Wallet.Open (Path => Path,
                           Info => Context.Info);

      if not Context.No_Password_Opt or else Context.Info.Header_Count = 0 then
         if Context.Key_Provider /= null then
            Context.Wallet.Set_Master_Key (Context.Key_Provider.all);
         end if;
         Context.Wallet.Unlock (Context.Provider.all, Context.Slot);
         Slot := Context.Slot;
         if Command.Slot'Length > 0 then
            Slot := Get_Slot (Command.Slot.all);
         end if;

         Context.Wallet.Remove_Key (Password => Context.Provider.all,
                                    Slot     => Slot,
                                    Force    => Command.Force);
      else
         Context.GPG.Load_Secrets (Context.Wallet);
         Context.Wallet.Set_Master_Key (Context.GPG);
         Context.Wallet.Unlock (Context.GPG, Context.Slot);
         Slot := Context.Slot;
         if Command.Slot'Length > 0 then
            Slot := Get_Slot (Command.Slot.all);
         end if;

         Context.Wallet.Remove_Key (Password => Context.GPG,
                                    Slot     => Slot,
                                    Force    => Command.Force);
      end if;

      Context.Console.Notice (N_INFO, -("The password was successfully removed."));

   exception
      when Keystore.Used_Key_Slot =>
         AKT.Commands.Log.Error (-("refusing to erase the key slot used by current password"));
         AKT.Commands.Log.Error (-("use the --force option if you really want "
                                 & "to erase this slot"));
         raise Error;

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
                        Output => Command.Force'Access,
                        Switch => "-f",
                        Long_Switch => "--force",
                        Help   => -("Force erase of password used to unlock the keystore"));
      GC.Define_Switch (Config => Config,
                        Output => Command.Slot'Access,
                        Switch => "-s:",
                        Long_Switch => "--slot:",
                        Argument => "SLOT",
                        Help   => -("Defines the key slot to erase in range 1..7"));
   end Setup;

end AKT.Commands.Password.Remove;
