-----------------------------------------------------------------------
--  keystore-properties-tests -- Tests for Keystore.Properties
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

with Util.Beans.Objects;
with Util.Test_Caller;
package body Keystore.Properties.Tests is

   package Caller is new Util.Test_Caller (Test, "Keystore.Properties");

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite) is
   begin
      Caller.Add_Test (Suite, "Test Keystore.Properties.Files",
                       Test_Properties'Access);
      Caller.Add_Test (Suite, "Test Keystore.Properties.Iterate",
                       Test_Iterate'Access);
   end Add_Tests;

   procedure Test_Properties (T     : in out Test;
                              Props : in out Util.Properties.Manager'Class) is
   begin
      Props.Set ("p1", "a");
      Props.Set ("p2", "b");
      Props.Set ("p3", "c");
      T.Assert (Props.Exists ("p1"), "Property 'p1' not found");
      T.Assert (Props.Exists ("p2"), "Property 'p2' not found");
      T.Assert (Props.Exists ("p3"), "Property 'p3' not found");
      T.Assert (not Props.Exists ("p4"), "Exists returned true for 'p4'");

      Util.Tests.Assert_Equals (T, "a", String '(Props.Get ("p1")), "Invalid property 'p1'");
      Util.Tests.Assert_Equals (T, "b", String '(Props.Get ("p2")), "Invalid property 'p2'");
      Util.Tests.Assert_Equals (T, "c", String '(Props.Get ("p3")), "Invalid property 'p3'");

      Props.Remove ("p2");
      T.Assert (not Props.Exists ("p2"), "Property 'p2' not removed");

      declare
         V : constant Util.Beans.Objects.Object := Props.Get_Value ("p5");
      begin
         T.Assert (Util.Beans.Objects.Is_Null (V), "Value should be null");
      end;
   end Test_Properties;

   --  ------------------------------
   --  Test the accessing the keystore through property manager.
   --  ------------------------------
   procedure Test_Properties (T : in out Test) is
      Path     : constant String := Util.Tests.Get_Test_Path ("regtests/result/test-prop.akt");
      Password : constant Keystore.Secret_Key := Keystore.Create ("mypassword");
      Wallet   : aliased Keystore.Files.Wallet_File;
      Props    : Keystore.Properties.Manager;
      Config   : Keystore.Wallet_Config := Unsecure_Config;
   begin
      Config.Overwrite := True;
      Props.Initialize (Wallet'Unchecked_Access);
      Wallet.Create (Path => Path, Password => Password, Config => Config);
      T.Test_Properties (Props);

      Wallet.Close;
      Wallet.Open (Path => Path, Password => Password);

      declare
         P3 : Keystore.Properties.Manager;
      begin
         P3 := Props;
         T.Test_Properties (P3);
      end;

      declare
         P2 : Util.Properties.Manager;
      begin
         Props.Copy (P2);
         T.Test_Properties (P2);
      end;
   end Test_Properties;

   --  ------------------------------
   --  Test iterating over the property manager.
   --  ------------------------------
   procedure Test_Iterate (T : in out Test) is
      use Util.Properties;
      procedure Process (Name : in String; Item : in Util.Properties.Value);

      Path     : constant String := Util.Tests.Get_Test_Path ("regtests/result/test-prop.akt");
      Password : constant Keystore.Secret_Key := Keystore.Create ("mypassword");
      Wallet   : aliased Keystore.Files.Wallet_File;
      Props    : Keystore.Properties.Manager;
      Config   : Keystore.Wallet_Config := Unsecure_Config;
      Count    : Natural := 0;

      procedure Process (Name : in String; Item : in Util.Properties.Value) is
      begin
         Count := Count + 1;
         if Name = "p1" then
            Util.Tests.Assert_Equals (T, "a", To_String (Item), "Invalid property " & Name);
         elsif Name = "p2" then
            Util.Tests.Assert_Equals (T, "b", To_String (Item), "Invalid property " & Name);
         elsif Name = "p3" then
            Util.Tests.Assert_Equals (T, "c", To_String (Item), "Invalid property " & Name);
         else
            T.Fail ("Invalid property " & Name);
         end if;
      end Process;

   begin
      Config.Overwrite := True;
      Props.Initialize (Wallet'Unchecked_Access);
      Wallet.Create (Path => Path, Password => Password, Config => Config);
      T.Test_Properties (Props);
      Props.Iterate (Process'Access);
      Wallet.Close;

   end Test_Iterate;

end Keystore.Properties.Tests;
