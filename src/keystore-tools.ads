-----------------------------------------------------------------------
--  keystore-tools -- Tools for the keystore
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Ada.Directories;

package Keystore.Tools is

   subtype Directory_Entry_Type is Ada.Directories.Directory_Entry_Type;

   --  Store the file in the keystore and use the prefix followed by the file basename
   --  for the name to identify the stored the content.
   procedure Store (Wallet  : in out Keystore.Wallet'Class;
                    Path    : in String;
                    Prefix  : in String);

   --  Scan the directory for files matching the pattern and store them in the
   --  keystore when the filter predicate accepts them.
   procedure Store (Wallet  : in out Keystore.Wallet'Class;
                    Path    : in String;
                    Prefix  : in String;
                    Pattern : in String;
                    Filter  : not null
                    access function (Ent : in Directory_Entry_Type) return Boolean);

end Keystore.Tools;
