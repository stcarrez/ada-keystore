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
with Gtk.Spin_Button;
with Gtk.Window;

with Util.Log.Loggers;

with Keystore;
package body AKT.Callbacks is

   use type Gtk.Spin_Button.Gtk_Spin_Button;
   use type Gtk.GEntry.Gtk_Entry;
   use type Gtk.Widget.Gtk_Widget;

   --  The logger
   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("AKT.Callbacks");

   App : AKT.Windows.Application_Access;

   function Get_Widget (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class;
                        Name   : in String) return Gtk.Widget.Gtk_Widget is
      (Gtk.Widget.Gtk_Widget (Object.Get_Object (Name)));

   function Get_Entry (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class;
                       Name   : in String) return Gtk.GEntry.Gtk_Entry is
      (Gtk.GEntry.Gtk_Entry (Object.Get_Object (Name)));

   function Get_Spin_Button (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class;
                             Name   : in String) return Gtk.Spin_Button.Gtk_Spin_Button is
      (Gtk.Spin_Button.Gtk_Spin_Button (Object.Get_Object (Name)));

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

      --  Open file from menu and dialog.
      Builder.Register_Handler (Handler_Name => "menu-open",
                                Handler      => AKT.Callbacks.On_Menu_Open'Access);
      Builder.Register_Handler (Handler_Name => "open-file",
                                Handler      => AKT.Callbacks.On_Open_File'Access);
      Builder.Register_Handler (Handler_Name => "cancel-open-file",
                                Handler      => AKT.Callbacks.On_Cancel_Open_File'Access);

      --  Create file from menu and dialog.
      Builder.Register_Handler (Handler_Name => "menu-new",
                                Handler      => AKT.Callbacks.On_Menu_New'Access);
      Builder.Register_Handler (Handler_Name => "create-file",
                                Handler      => AKT.Callbacks.On_Create_File'Access);
      Builder.Register_Handler (Handler_Name => "cancel-create-file",
                                Handler      => AKT.Callbacks.On_Cancel_Create_File'Access);

      Builder.Register_Handler (Handler_Name => "window-close",
                                Handler      => AKT.Callbacks.On_Close_Window'Access);
      Builder.Register_Handler (Handler_Name => "about",
                                Handler      => AKT.Callbacks.On_Menu_About'Access);
      Builder.Register_Handler (Handler_Name => "close-about",
                                Handler      => AKT.Callbacks.On_Close_About'Access);
      Builder.Register_Handler (Handler_Name => "close-password",
                                Handler      => AKT.Callbacks.On_Close_Password'Access);
      Builder.Register_Handler (Handler_Name => "tool-edit",
                                Handler      => AKT.Callbacks.On_Tool_Edit'Access);
      Builder.Register_Handler (Handler_Name => "tool-lock",
                                Handler      => AKT.Callbacks.On_Tool_Lock'Access);
      Builder.Register_Handler (Handler_Name => "tool-unlock",
                                Handler      => AKT.Callbacks.On_Tool_Unlock'Access);
      Builder.Register_Handler (Handler_Name => "tool-save",
                                Handler      => AKT.Callbacks.On_Tool_Save'Access);
      Builder.Register_Handler (Handler_Name => "tool-add",
                                Handler      => AKT.Callbacks.On_Tool_Add'Access);
      Builder.Register_Handler (Handler_Name => "dialog-password-ok",
                                Handler      => AKT.Callbacks.On_Dialog_Password_Ok'Access);
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
      About : constant Gtk.Widget.Gtk_Widget := Get_Widget (Object, "about");
   begin
      About.Show;
   end On_Menu_About;

   --  ------------------------------
   --  Callback executed when the "menu-new" action is executed from the file menu.
   --  ------------------------------
   procedure On_Menu_New (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class) is
      Chooser : constant Gtk.Widget.Gtk_Widget := Get_Widget (Object, "create_file_chooser");
      Filter  : Gtk.File_Filter.Gtk_File_Filter;
      File_Chooser : Gtk.File_Chooser.Gtk_File_Chooser;
   begin
      if Chooser /= null then
         File_Chooser := Gtk.File_Chooser_Dialog."+"
           (Gtk.File_Chooser_Dialog.Gtk_File_Chooser_Dialog (Chooser));

         Gtk.File_Filter.Gtk_New (Filter);
         Gtk.File_Filter.Add_Pattern (Filter, "*.akt");
         Gtk.File_Filter.Set_Name (Filter, "Keystore Files");
         Gtk.File_Chooser.Add_Filter (File_Chooser, Filter);

         Gtk.File_Filter.Gtk_New (Filter);
         Gtk.File_Filter.Add_Pattern (Filter, "*");
         Gtk.File_Filter.Set_Name (Filter, "All Files");
         Gtk.File_Chooser.Add_Filter (File_Chooser, Filter);

      end if;
      Chooser.Show;
   end On_Menu_New;

   --  ------------------------------
   --  Callback executed when the "menu-open" action is executed from the file menu.
   --  ------------------------------
   procedure On_Menu_Open (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class) is
      Chooser : constant Gtk.Widget.Gtk_Widget := Get_Widget (Object, "open_file_chooser");
      Filter  : Gtk.File_Filter.Gtk_File_Filter;
      File_Chooser : Gtk.File_Chooser.Gtk_File_Chooser;
   begin
      if Chooser /= null then
         File_Chooser := Gtk.File_Chooser_Dialog."+"
           (Gtk.File_Chooser_Dialog.Gtk_File_Chooser_Dialog (Chooser));

         Gtk.File_Filter.Gtk_New (Filter);
         Gtk.File_Filter.Add_Pattern (Filter, "*.akt");
         Gtk.File_Filter.Set_Name (Filter, "Keystore Files");
         Gtk.File_Chooser.Add_Filter (File_Chooser, Filter);

         Gtk.File_Filter.Gtk_New (Filter);
         Gtk.File_Filter.Add_Pattern (Filter, "*");
         Gtk.File_Filter.Set_Name (Filter, "All Files");
         Gtk.File_Chooser.Add_Filter (File_Chooser, Filter);

      end if;
      Chooser.Show;
   end On_Menu_Open;

   --  ------------------------------
   --  Callback executed when the "tool-add" action is executed from the toolbar.
   --  ------------------------------
   procedure On_Tool_Add (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class) is
   begin
      App.Save_Current;
      App.Refresh_Toolbar;
   end On_Tool_Add;

   --  ------------------------------
   --  Callback executed when the "tool-save" action is executed from the toolbar.
   --  ------------------------------
   procedure On_Tool_Save (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class) is
   begin
      App.Save_Current;
      App.Refresh_Toolbar;
   end On_Tool_Save;

   --  ------------------------------
   --  Callback executed when the "tool-edit" action is executed from the toolbar.
   --  ------------------------------
   procedure On_Tool_Edit (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class) is
   begin
      App.Edit_Current;
      App.Refresh_Toolbar;
   end On_Tool_Edit;

   --  ------------------------------
   --  Callback executed when the "tool-lock" action is executed from the toolbar.
   --  ------------------------------
   procedure On_Tool_Lock (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class) is
   begin
      if not App.Is_Locked then
         App.Lock;
      end if;
   end On_Tool_Lock;

   --  ------------------------------
   --  Callback executed when the "tool-unlock" action is executed from the toolbar.
   --  ------------------------------
   procedure On_Tool_Unlock (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class) is
      Password_Dialog : constant Gtk.Widget.Gtk_Widget := Get_Widget (Object, "password_dialog");
      Widget          : constant Gtk.Widget.Gtk_Widget := Get_Widget (Object, "main");
   begin
      if App.Is_Locked and then Password_Dialog /= null then
         Gtk.Window.Set_Transient_For (Gtk.Window.Gtk_Window (Password_Dialog),
                                       Gtk.Window.Gtk_Window (Widget));
         Password_Dialog.Show;
      end if;
   end On_Tool_Unlock;

   --  ------------------------------
   --  Callback executed when the "open-file" action is executed from the open_file dialog.
   --  ------------------------------
   procedure On_Open_File (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class) is
      Chooser  : constant Gtk.Widget.Gtk_Widget := Get_Widget (Object, "open_file_chooser");
      Password : constant Gtk.GEntry.Gtk_Entry := Get_Entry (Object, "open_file_password");
      Filename : constant Gtk.GEntry.Gtk_Entry := Get_Entry (Object, "open_file_name");
      File_Chooser : Gtk.File_Chooser.Gtk_File_Chooser;
   begin
      if Chooser /= null and Password /= null and Filename /= null then
         if Gtk.GEntry.Get_Text (Password) = "" then
            App.Message ("Password is empty");
         else
            Chooser.Hide;
            File_Chooser := Gtk.File_Chooser_Dialog."+"
              (Gtk.File_Chooser_Dialog.Gtk_File_Chooser_Dialog (Chooser));
            Log.Info ("Selected file {0}", Gtk.File_Chooser.Get_Filename (File_Chooser));
            App.Open_File (Path     => Gtk.File_Chooser.Get_Filename (File_Chooser),
                           Password => Keystore.Create (Gtk.GEntry.Get_Text (Password)));
         end if;
      end if;
   end On_Open_File;

   --  ------------------------------
   --  Callback executed when the "cancel-open-file" action is executed from the open_file dialog.
   --  ------------------------------
   procedure On_Cancel_Open_File (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class) is
      Chooser : constant Gtk.Widget.Gtk_Widget := Get_Widget (Object, "open_file_chooser");
   begin
      Chooser.Hide;
   end On_Cancel_Open_File;

   --  ------------------------------
   --  Callback executed when the "create-file" action is executed from the open_file dialog.
   --  ------------------------------
   procedure On_Create_File (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class) is
      Chooser  : constant Gtk.Widget.Gtk_Widget := Get_Widget (Object, "create_file_chooser");
      Password : constant Gtk.GEntry.Gtk_Entry := Get_Entry (Object, "create_file_password");
      Filename : constant Gtk.GEntry.Gtk_Entry := Get_Entry (Object, "create_file_name");
      Count    : constant Gtk.Spin_Button.Gtk_Spin_Button := Get_Spin_Button (Object, "split_data_count");
      File_Chooser : Gtk.File_Chooser.Gtk_File_Chooser;
   begin
      if Chooser /= null and Password /= null then
         if Gtk.GEntry.Get_Text (Password) = "" then
            App.Message ("Password is empty");
         else
            Chooser.Hide;
            File_Chooser := Gtk.File_Chooser_Dialog."+"
              (Gtk.File_Chooser_Dialog.Gtk_File_Chooser_Dialog (Chooser));
            Log.Info ("Selected file {0}", Gtk.File_Chooser.Get_Filename (File_Chooser));
            App.Create_File (Path     => Gtk.GEntry.Get_Text (Filename),
                             Storage_Count => Natural (Count.Get_Value_As_Int),
                             Password => Keystore.Create (Gtk.GEntry.Get_Text (Password)));
         end if;
      end if;
   end On_Create_File;

   --  ------------------------------
   --  Callback executed when the "cancel-create-file" action is executed
   --  from the open_file dialog.
   --  ------------------------------
   procedure On_Cancel_Create_File (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class) is
      Chooser : constant Gtk.Widget.Gtk_Widget := Get_Widget (Object, "create_file_chooser");
   begin
      Chooser.Hide;
   end On_Cancel_Create_File;

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
      About : constant Gtk.Widget.Gtk_Widget := Get_Widget (Object, "about");
   begin
      About.Hide;
   end On_Close_About;

   --  ------------------------------
   --  Callback executed when the "close-password" action is executed from the password dialog.
   --  ------------------------------
   procedure On_Close_Password (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class) is
      Password_Dialog : constant Gtk.Widget.Gtk_Widget := Get_Widget (Object, "password_dialog");
   begin
      if Password_Dialog /= null then
         Password_Dialog.Hide;
      end if;
   end On_Close_Password;

   --  ------------------------------
   --  Callback executed when the "dialog-password-ok" action is executed from the password dialog.
   --  ------------------------------
   procedure On_Dialog_Password_Ok (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class) is
      Password_Dialog : constant Gtk.Widget.Gtk_Widget := Get_Widget (Object, "password_dialog");
      Password : constant Gtk.GEntry.Gtk_Entry := Get_Entry (Object, "password");
   begin
      if Password_Dialog /= null and Password /= null then
         if Gtk.GEntry.Get_Text (Password) = "" then
            App.Message ("Password is empty");
         else
            Password_Dialog.Hide;

            App.Unlock (Password => Keystore.Create (Gtk.GEntry.Get_Text (Password)));
         end if;
      end if;
   end On_Dialog_Password_Ok;

end AKT.Callbacks;
