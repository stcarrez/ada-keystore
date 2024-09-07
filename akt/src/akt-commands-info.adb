-----------------------------------------------------------------------
--  akt-commands-info -- Info command of keystore
--  Copyright (C) 2019, 2022, 2024 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with Keystore.Verifier;
package body AKT.Commands.Info is

   use type Keystore.Header_Slot_Count_Type;
   use type Keystore.Passwords.Keys.Key_Provider_Access;

   --  ------------------------------
   --  List the value entries of the keystore.
   --  ------------------------------
   overriding
   procedure Execute (Command   : in out Command_Type;
                      Name      : in String;
                      Args      : in Argument_List'Class;
                      Context   : in out Context_Type) is
      pragma Unreferenced (Command, Name);
      function Get_Stat_Info (Stats : in Keystore.Wallet_Stats) return String;

      function Get_Stat_Info (Stats : in Keystore.Wallet_Stats) return String is
         Slots : String (1 .. Stats.Keys'Length * 2) := (others => ' ');
         C     : Character := '1';
      begin
         for Slot in Stats.Keys'Range loop
            if Stats.Keys (Slot) then
               Slots (Positive (Slot) * 2) := C;
            end if;
            C := Character'Succ (C);
         end loop;
         return Slots;
      end Get_Stat_Info;

      Path  : constant String := Context.Get_Keystore_Path (Args);
      Stats : Keystore.Wallet_Stats;
      Is_Keystore : Boolean;
   begin
      Keystore.Verifier.Print_Information (Path, Is_Keystore);

      --  No need to proceed if this is not a keystore file.
      if not Is_Keystore then
         return;
      end if;

      Setup_Password_Provider (Context);
      Setup_Key_Provider (Context);

      Context.Wallet.Open (Path => Path,
                           Data_Path => Context.Data_Path.all,
                           Info => Context.Info);
      if Context.No_Password_Opt and then Context.Info.Header_Count = 0 then
         return;
      end if;
      if not Context.No_Password_Opt then
         if Context.Key_Provider /= null then
            Context.Wallet.Set_Master_Key (Context.Key_Provider.all);
         end if;
         Context.Wallet.Unlock (Context.Provider.all, Context.Slot);
      else
         Context.GPG.Load_Secrets (Context.Wallet);
         Context.Wallet.Set_Master_Key (Context.GPG);
         Context.Wallet.Unlock (Context.GPG, Context.Slot);
      end if;

      Context.Wallet.Get_Stats (Stats);
      Context.Console.Clear_Fields;
      Context.Console.Set_Field_Length (1, 30);
      Context.Console.Set_Field_Length (2, 70);
      Context.Console.Start_Row;
      Context.Console.Print_Field (1, -("Key slots used: "));
      Context.Console.Print_Field (2, Get_Stat_Info (Stats));
      Context.Console.End_Row;

      Context.Console.Print_Field (1, -("Entry count: "));
      Context.Console.Print_Field (2, Stats.Entry_Count);
      Context.Console.End_Row;

   end Execute;

end AKT.Commands.Info;
