-----------------------------------------------------------------------
--  keystore-gpg -- helpers to open keystores protected with GPG
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

package body Keystore.GPG is

   --  ------------------------------
   --  Open the keystore file and unlock the wallet using GPG.
   --  Raises the Bad_Password exception if no key slot match an available GPG key.
   --  ------------------------------
   procedure Open (Container : in out Wallet_File;
                   Context   : in out Context_Type;
                   Path      : in String;
                   Data_Path : in String := "";
                   Config    : in Wallet_Config := Secure_Config) is
      Info : Keystore.Wallet_Info;
      Slot : Key_Slot;
   begin
      Container.Open (Path   => Path, Data_Path => Data_Path,
                      Config => Config, Info => Info);
      if Info.Header_Count = 0 then
         raise Bad_Password with "No password to unlock the keystore";
      end if;
      Context.Load_Secrets (Container);
      Container.Set_Master_Key (Context);
      Container.Unlock (Context, Slot);
   end Open;

end Keystore.GPG;
