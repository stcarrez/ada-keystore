-----------------------------------------------------------------------
--  keystore-testsuite -- Testsuite for keystore
--  Copyright (C) 2019, 2025 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Util.Tests;
package Keystore.Testsuite is

   function Suite return Util.Tests.Access_Test_Suite;

   function Tool return String;

end Keystore.Testsuite;
