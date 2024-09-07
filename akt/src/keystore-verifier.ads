-----------------------------------------------------------------------
--  keystore-verifier -- Toolbox to explore raw content of keystore
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

package Keystore.Verifier is

   procedure Print_Information (Path        : in String;
                                Is_Keystore : out Boolean);

end Keystore.Verifier;
