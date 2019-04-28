-----------------------------------------------------------------------
--  akt-windows -- GtK Windows for Ada Keystore GTK application
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
with Ada.Finalization;
with Gtk.Widget;
with Gtk.Status_Bar;
with Gtk.Tree_View;
with Gtk.Tree_Store;
with Gtk.Tree_Model;
with Gtk.Cell_Renderer_Text;
with Gtk.Scrolled_Window;
with Gtk.Frame;
with Gtk.Viewport;
with Gtkada.Builder;
with Keystore.Files;
package AKT.Windows is

   type Application_Type is limited new Ada.Finalization.Limited_Controlled with private;
   type Application_Access is access all Application_Type;

   --  Initialize the target instance.
   overriding
   procedure Initialize (Application : in out Application_Type);

   --  Release the storage.
   overriding
   procedure Finalize (Application : in out Application_Type);

   --  Initialize the widgets and create the Gtk gui.
   procedure Initialize_Widget (Application : in out Application_Type;
                                Widget : out Gtk.Widget.Gtk_Widget);

   procedure Open_File (Application : in out Application_Type;
                        Path        : in String;
                        Password    : in Keystore.Secret_Key);

   --  Set the UI label with the given value.
   procedure Set_Label (Application : in Application_Type;
                        Name   : in String;
                        Value  : in String);

   procedure List_Keystore (Application : in out Application_Type);

   procedure Main (Application : in out Application_Type);

private

   --  Load the glade XML definition.
   procedure Load_UI (Application : in out Application_Type);

   type Application_Type is limited new Ada.Finalization.Limited_Controlled with record
      Builder     : Gtkada.Builder.Gtkada_Builder;
      Previous_Event_Counter : Integer := 0;
      Main        : Gtk.Widget.Gtk_Widget;
      About       : Gtk.Widget.Gtk_Widget;
      Chooser     : Gtk.Widget.Gtk_Widget;
      Status      : Gtk.Status_Bar.Gtk_Status_Bar;
      Wallet      : Keystore.Files.Wallet_File;
      Frame       : Gtk.Frame.Gtk_Frame;
      Scrolled    : Gtk.Scrolled_Window.Gtk_Scrolled_Window;
      Viewport    : Gtk.Viewport.Gtk_Viewport;
      List        : Gtk.Tree_Store.Gtk_Tree_Store;
      Current_Row : Gtk.Tree_Model.Gtk_Tree_Iter;
      Tree        : Gtk.Tree_View.Gtk_Tree_View;
      Col_Text    : Gtk.Cell_Renderer_Text.Gtk_Cell_renderer_Text;
   end record;

end AKT.Windows;
