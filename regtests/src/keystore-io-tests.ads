-----------------------------------------------------------------------
--  keystore-io-tests -- Tests for keystore IO
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Util.Tests;
package Keystore.IO.Tests is

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite);

   type Test is new Util.Tests.Test with null record;

   procedure Test_File_IO (T : in out Test);

   procedure Test_Perf_IO (T : in out Test);

end Keystore.IO.Tests;
