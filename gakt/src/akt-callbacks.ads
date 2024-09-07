-----------------------------------------------------------------------
--  akt-callbacks -- Callbacks for Ada Keystore GTK application
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with Gtkada.Builder;

with AKT.Windows;
package AKT.Callbacks is

   --  Initialize and register the callbacks.
   procedure Initialize (Application : in AKT.Windows.Application_Access;
                         Builder     : in Gtkada.Builder.Gtkada_Builder);

   --  Callback executed when the "quit" action is executed from the menu.
   procedure On_Menu_Quit (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class);

   --  Callback executed when the "about" action is executed from the menu.
   procedure On_Menu_About (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class);

   --  Callback executed when the "menu-new" action is executed from the file menu.
   procedure On_Menu_New (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class);

   --  Callback executed when the "menu-open" action is executed from the file menu.
   procedure On_Menu_Open (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class);

   --  Callback executed when the "tool-add" action is executed from the toolbar.
   procedure On_Tool_Add (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class);

   --  Callback executed when the "tool-save" action is executed from the toolbar.
   procedure On_Tool_Save (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class);

   --  Callback executed when the "tool-edit" action is executed from the toolbar.
   procedure On_Tool_Edit (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class);

   --  Callback executed when the "tool-lock" action is executed from the toolbar.
   procedure On_Tool_Lock (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class);

   --  Callback executed when the "tool-unlock" action is executed from the toolbar.
   procedure On_Tool_Unlock (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class);

   --  Callback executed when the "open-file" action is executed from the open_file dialog.
   procedure On_Open_File (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class);

   --  Callback executed when the "cancel-open-file" action is executed from the open_file dialog.
   procedure On_Cancel_Open_File (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class);

   --  Callback executed when the "create-file" action is executed from the open_file dialog.
   procedure On_Create_File (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class);

   --  Callback executed when the "cancel-create-file" action is executed
   --  from the open_file dialog.
   procedure On_Cancel_Create_File (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class);

   --  Callback executed when the "delete-event" action is executed from the main window.
   function On_Close_Window (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class)
                             return Boolean;

   --  Callback executed when the "close-about" action is executed from the about box.
   procedure On_Close_About (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class);

   --  Callback executed when the "close-password" action is executed from the password dialog.
   procedure On_Close_Password (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class);

   --  Callback executed when the "dialog-password-ok" action is executed from the password dialog.
   procedure On_Dialog_Password_Ok (Object : access Gtkada.Builder.Gtkada_Builder_Record'Class);

end AKT.Callbacks;
