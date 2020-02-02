-----------------------------------------------------------------------
--  keystore-properties -- Property manager on top of keystore
--  Copyright (C) 2020 Stephane Carrez
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

   overriding
   procedure Adjust (Object : in out Manager);

end Keystore.Properties;
