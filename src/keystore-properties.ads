-----------------------------------------------------------------------
--  keystore-properties -- Property manager on top of keystore
--  Copyright (C) 2020 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Util.Properties;
with Keystore.Files; use Keystore;

package Keystore.Properties is

   type Wallet_File_Access is access all Keystore.Files.Wallet_File'Class;

   type Manager is new Util.Properties.Manager with private;

   procedure Initialize (Props  : in out Manager'Class;
                         Wallet : in Wallet_File_Access);

private

   type Manager is new Util.Properties.Manager with null record;

   overriding
   procedure Initialize (Object : in out Manager);

end Keystore.Properties;
