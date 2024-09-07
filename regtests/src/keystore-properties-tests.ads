-----------------------------------------------------------------------
--  keystore-properties-tests -- Tests for Keystore.Properties
--  Copyright (C) 2020 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Util.Properties;
with Util.Tests;
package Keystore.Properties.Tests is

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite);

   type Test is new Util.Tests.Test with null record;

   procedure Test_Properties (T     : in out Test;
                              Props : in out Util.Properties.Manager'Class);

   --  Test the accessing the keystore through property manager.
   procedure Test_Properties (T : in out Test);

   --  Test iterating over the property manager.
   procedure Test_Iterate (T : in out Test);

end Keystore.Properties.Tests;
