-----------------------------------------------------------------------
--  keystore-gpg -- helpers to open keystores protected with GPG
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
