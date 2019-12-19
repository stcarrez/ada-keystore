-----------------------------------------------------------------------
--  akt-gtk -- Ada Keystore Tool GTK Application
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--
--  Licensed under the Apache License, Version 2.0 (the "License");
--  you may not use this file except in compliance with the License.
--  You may obtain a copy of the License at
--
--      http://www.apache.org/licenses/LICENSE-2.0
--
--  Unless required by applicable law or agreed to in writing, software
--  distributed under the License is distributed on an "AS IS" BASIS,
--  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
--  See the License for the specific language governing permissions and
--  limitations under the License.
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
