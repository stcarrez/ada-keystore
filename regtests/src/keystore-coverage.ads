-----------------------------------------------------------------------
--  keystore-coverage -- Specific tests for coverage
--  Copyright (C) 2020 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Util.Tests;
private package Keystore.Coverage is

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite);

   type Test is new Util.Tests.Test with null record;

   procedure Test_Deep_Coverage (T : in out Test);

end Keystore.Coverage;
