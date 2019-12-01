-----------------------------------------------------------------------
--  akt-commands-info -- Info command of keystore
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
      if Context.No_Password_Opt and Context.Info.Header_Count = 0 then
         return;
      end if;
      if not Context.No_Password_Opt then
         if Context.Key_Provider /= null then
            Context.Wallet.Set_Master_Key (Context.Key_Provider.all);
         end if;
         Context.Wallet.Unlock (Context.Provider.all, Context.Slot);
      else
         Context.GPG.Load_Secrets (Context.Wallet);
         Context.Wallet.Unlock (Context.GPG, Context.Slot);
      end if;

      Context.Wallet.Get_Stats (Stats);
      Ada.Text_IO.Put ("Key slots used: ");
      Ada.Text_IO.Set_Col (29);
      for Slot in Stats.Keys'Range loop
         if Stats.Keys (Slot) then
            Ada.Text_IO.Put (Keystore.Key_Slot'Image (Slot));
         end if;
      end loop;

      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put ("Entry count: ");
      Ada.Text_IO.Set_Col (29);
      Ada.Text_IO.Put_Line (Natural'Image (Stats.Entry_Count));

   end Execute;

end AKT.Commands.Info;
