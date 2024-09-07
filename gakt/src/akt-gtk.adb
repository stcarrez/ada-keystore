-----------------------------------------------------------------------
--  akt-gtk -- Ada Keystore Tool GTK Application
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Ada.Command_Line;
with Gtk.Widget; use Gtk;
with AKT.Windows;
procedure AKT.Gtk is
   Main        : Widget.Gtk_Widget;
   Application : aliased AKT.Windows.Application_Type;
begin
   AKT.Configure_Logs (Debug   => False,
                       Dump    => False,
                       Verbose => False);
   Application.Initialize_Widget (Main);
   Application.Main;

exception
   when AKT.Windows.Initialize_Error =>
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);

   when E : others =>
      AKT.Windows.Log.Error ("Error while starting", E, Trace => True);
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);

end AKT.Gtk;
