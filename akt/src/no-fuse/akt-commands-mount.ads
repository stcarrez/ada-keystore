-----------------------------------------------------------------------
--  akt-commands-mount -- Mount the keystore on the filesystem for direct access
--  Copyright (C) 2019, 2020 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with AKT.Commands.Drivers;
private package AKT.Commands.Mount is

   HAS_FUSE : constant Boolean := False;

   procedure Register (Driver : in out Drivers.Driver_Type) is null;

end AKT.Commands.Mount;
