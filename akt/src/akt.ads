-----------------------------------------------------------------------
--  akt -- Ada Keystore Tool
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with Intl;
package AKT is

   function "-" (Message : in String) return String is (Intl."-" (Message));

   No_Keystore_File : exception;

private

   --  Configure the logs.
   procedure Configure_Logs (Debug   : in Boolean;
                             Dump    : in Boolean;
                             Verbose : in Boolean);

end AKT;
