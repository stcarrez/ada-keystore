-----------------------------------------------------------------------
--  akt-windows -- GtK Windows for Ada Keystore GTK application
--  Copyright (C) 2019, 2020 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
separate (AKT.Windows)

--  ------------------------------
--  Load the glade XML definition.
--  ------------------------------
procedure Load_UI (Application : in out Application_Type) is
   use type Glib.Guint;

   Result : Glib.Guint;
   Error  : aliased Glib.Error.GError;
begin
   Result := Application.Builder.Add_From_File ("gakt.glade", Error'Access);
   if Result /= 1 then
      Log.Error ("Cannot load the 'gakt.glade' configuration file");
      raise Initialize_Error;
   end if;
end Load_UI;
