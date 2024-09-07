-----------------------------------------------------------------------
--  Keystore-test -- Unit tests
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Ada.Environment_Variables;
with Util.Tests;
with Keystore.Testsuite;

procedure Keystore_Harness is

   procedure Harness is new Util.Tests.Harness (Keystore.Testsuite.Suite);

begin
   --  Force the language to be English since some tests will verify some message.
   Ada.Environment_Variables.Set ("LANG", "en");
   Ada.Environment_Variables.Set ("LANGUAGE", "en");
   Harness ("keystore-tests.xml");
end Keystore_Harness;
