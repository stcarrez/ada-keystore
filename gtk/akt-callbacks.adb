-----------------------------------------------------------------------
--  akt-callbacks -- Callbacks for Ada Keystore GTK application
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

with Gtk.Main;
with Gtk.Widget;
with Gtk.GEntry;
with Gtk.File_Filter;
with Gtk.File_Chooser;
with Gtk.File_Chooser_Dialog;

with Util.Log.Loggers;

with Keystore;
package body AKT.Callbacks is

   use type Gtk.GEntry.Gtk_Entry;
   use type Gtk.Widget.Gtk_Widget;

   --  The logger
   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("AKT.Callbacks");

   App : AKT.Windows.Application_Access;

   --  ------------------------------
   --  Initialize and register the callbacks.
   --  ------------------------------
   procedure Initialize (Application : in AKT.Windows.Application_Access;
                         Builder     : in Gtkada.Builder.Gtkada_Builder) is
   begin
      App := Application;

      --  AKT.Callbacks.Application := Application;
      Builder.Register_Handler (Handler_Name => "menu-quit",
                                Handler      => AKT.Callbacks.On_Menu_Quit'Access);

      --  Open file from menu and dialog
      Builder.Register_Handler (Handler_Name => "menu-open",
                                Handler      => AKT.Callbacks.On_Menu_Open'Access);
      Builder.Register_Handler (Handler_Name => "open-file",
                                Handler      => AKT.Callbacks.On_Open_File'Access);
      Builder.Register_Handler (Handler_Name => "cancel-open-file",
                                Handler      => AKT.Callbacks.On_Cancel_Open_File'Access);

      Builder.Register_Handler (Handler_Name => "menu-new",
                                Handler      => AKT.Callbacks.On_Menu_Open'Access);
      Builder.Register_Handler (Handler_Name => "menu-create",
                                Handler      => AKT.Callbacks.On_Menu_Create'Access);
      Builder.Register_Handler (Handler_Name => "window-close",
                                Handler      => AKT.Callbacks.On_Close_Window'Access);
      Builder.Register_Handler (Handler_Name => "about",
                                Handler      => AKT.Callbacks.On_Menu_About'Access);
      Builder.Register_Handler (Handler_Name => "close-about",
                                Handler      => AKT.Callbacks.On_Close_About'Access);
      Builder.Register_Handler (Handler_Name => "close-password",
                                Handler      => AKT.Callbacks.On_Close_Password'Access);
   end Initialize;

   --  ------------------------------
   --  Callback executed when the "quit" action is executed from the menu.
   --  ------------------------------
   procedure On_Menu_Quit (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class) is
      pragma Unreferenced (Object);
   begin
      Gtk.Main.Main_Quit;
   end On_Menu_Quit;

   --  ------------------------------
   --  Callback executed when the "about" action is executed from the menu.
   --  ------------------------------
   procedure On_Menu_About (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class) is
      About : constant Gtk.Widget.Gtk_Widget :=
        Gtk.Widget.Gtk_Widget (Object.Get_Object ("about"));
   begin
      About.Show;
   end On_Menu_About;

   --  Callback executed when the "menu-create" action is executed from the file menu.
   procedure On_Menu_Create (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class) is
   begin
      null;
   end On_Menu_Create;

   --  ------------------------------
   --  Callback executed when the "menu-open" action is executed from the file menu.
   --  ------------------------------
   procedure On_Menu_Open (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class) is
      Chooser : constant Gtk.Widget.Gtk_Widget
        := Gtk.Widget.Gtk_Widget (Object.Get_Object ("open_file_chooser"));
      File_Chooser : Gtk.File_Chooser.Gtk_File_Chooser;
      Filter  : Gtk.File_Filter.Gtk_File_Filter;
   begin
      Gtk.File_Filter.Gtk_New (Filter);
      Gtk.File_Filter.Add_Pattern (Filter, "*.akt");
      Gtk.File_Filter.Set_Name (Filter, "Keystore Files");

      Gtk.File_Filter.Gtk_New (Filter);
      Gtk.File_Filter.Add_Pattern (Filter, "*");
      Gtk.File_Filter.Set_Name (Filter, "All Files");
      if Chooser /= null then
         File_Chooser := Gtk.File_Chooser_Dialog."+"
           (Gtk.File_Chooser_Dialog.Gtk_File_Chooser_Dialog (Chooser));
         Gtk.File_Chooser.Add_Filter (File_Chooser, Filter);

         Gtk.File_Chooser.Add_Filter (File_Chooser, Filter);

      end if;
      Chooser.Show;
   end On_Menu_Open;

   --  ------------------------------
   --  Callback executed when the "open-file" action is executed from the open_file dialog.
   --  ------------------------------
   procedure On_Open_File (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class) is
      Chooser : constant Gtk.Widget.Gtk_Widget
        := Gtk.Widget.Gtk_Widget (Object.Get_Object ("open_file_chooser"));
      File_Chooser : Gtk.File_Chooser.Gtk_File_Chooser;
      Password : constant Gtk.GEntry.Gtk_Entry
        := Gtk.GEntry.Gtk_Entry (Object.Get_Object ("open_file_password"));
   begin
      Chooser.Hide;
      if Chooser /= null and Password /= null then
         File_Chooser := Gtk.File_Chooser_Dialog."+"
           (Gtk.File_Chooser_Dialog.Gtk_File_Chooser_Dialog (Chooser));
         Log.Info ("Selected file {0}", Gtk.File_Chooser.Get_Filename (File_Chooser));
         App.Open_File (Path     => Gtk.File_Chooser.Get_Filename (File_Chooser),
                        Password => Keystore.Create (Gtk.GEntry.Get_Text (Password)));
      end if;
   end On_Open_File;

   --  ------------------------------
   --  Callback executed when the "cancel-open-file" action is executed from the open_file dialog.
   --  ------------------------------
   procedure On_Cancel_Open_File (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class) is
      Chooser : constant Gtk.Widget.Gtk_Widget :=
        Gtk.Widget.Gtk_Widget (Object.Get_Object ("open_file_chooser"));
   begin
      Chooser.Hide;
   end On_Cancel_Open_File;

   --  ------------------------------
   --  Callback executed when the "delete-event" action is executed from the main window.
   --  ------------------------------
   function On_Close_Window (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class)
                             return Boolean is
      pragma Unreferenced (Object);
   begin
      Gtk.Main.Main_Quit;
      return True;
   end On_Close_Window;

   --  ------------------------------
   --  Callback executed when the "close-about" action is executed from the about box.
   --  ------------------------------
   procedure On_Close_About (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class) is
      About : constant Gtk.Widget.Gtk_Widget :=
        Gtk.Widget.Gtk_Widget (Object.Get_Object ("about"));
   begin
      About.Hide;
   end On_Close_About;

   --  ------------------------------
   --  Callback executed when the "close-password" action is executed from the password dialog.
   --  ------------------------------
   procedure On_Close_Password (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class) is
   begin
      null;
   end On_Close_Password;

end AKT.Callbacks;
