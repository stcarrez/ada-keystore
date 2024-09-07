-----------------------------------------------------------------------
--  akt-windows -- GtK Windows for Ada Keystore GTK application
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with Ada.Finalization;
with Gtk.Widget;
with Gtkada.Builder;
with Keystore.Files;
with Keystore.Passwords.GPG;
with Util.Log.Loggers;
private with Ada.Strings.Unbounded;
private with Gtk.Scrolled_Window;
private with Gtk.Frame;
private with Gtk.Viewport;
private with Gtk.Status_Bar;
private with Gtk.Tree_View;
private with Gtk.Tree_Store;
private with Gtk.Tree_Model;
private with Gtk.Tree_Selection;
private with Gtk.Cell_Renderer_Text;
private with Gtk.Text_Buffer;
private with Gtk.Text_View;
package AKT.Windows is

   Initialize_Error : exception;

   --  The logger
   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("AKT.Windows");

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

   procedure Create_File (Application   : in out Application_Type;
                          Path          : in String;
                          Storage_Count : in Natural;
                          Password      : in Keystore.Secret_Key);

   --  Set the UI label with the given value.
   procedure Set_Label (Application : in Application_Type;
                        Name   : in String;
                        Value  : in String);

   procedure List_Keystore (Application : in out Application_Type);

   procedure Edit_Value (Application : in out Application_Type;
                         Name        : in String);

   procedure Edit_Current (Application : in out Application_Type);

   procedure Save_Current (Application : in out Application_Type);

   --  Lock the keystore so that it is necessary to ask the password again to see/edit items.
   procedure Lock (Application : in out Application_Type);

   --  Unlock the keystore with the password.
   procedure Unlock (Application : in out Application_Type;
                     Password    : in Keystore.Secret_Key);

   --  Return True if the keystore is locked.
   function Is_Locked (Application : in Application_Type) return Boolean;

   --  Return True if the keystore is open.
   function Is_Open (Application : in Application_Type) return Boolean;

   procedure Main (Application : in out Application_Type);

   --  Report a message in the status area.
   procedure Message (Application : in out Application_Type;
                      Message     : in String);

   procedure Refresh_Toolbar (Application : in out Application_Type);

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
      Info        : Keystore.Wallet_Info;
      Config      : Keystore.Wallet_Config := Keystore.Secure_Config;
      GPG         : Keystore.Passwords.GPG.Context_Type;
      Slot        : Keystore.Key_Slot;
      Path        : Ada.Strings.Unbounded.Unbounded_String;
      Frame       : Gtk.Frame.Gtk_Frame;
      Scrolled    : Gtk.Scrolled_Window.Gtk_Scrolled_Window;
      Viewport    : Gtk.Viewport.Gtk_Viewport;
      List        : Gtk.Tree_Store.Gtk_Tree_Store;
      Current_Row : Gtk.Tree_Model.Gtk_Tree_Iter;
      Tree        : Gtk.Tree_View.Gtk_Tree_View;
      Selection   : Gtk.Tree_Selection.Gtk_Tree_Selection;
      Col_Text    : Gtk.Cell_Renderer_Text.Gtk_Cell_Renderer_Text;
      Editor      : Gtk.Text_View.Gtk_Text_View;
      Buffer      : Gtk.Text_Buffer.Gtk_Text_Buffer;
      Current     : Ada.Strings.Unbounded.Unbounded_String;
      Editing     : Boolean := False;
      Locked      : Boolean := False;
   end record;

end AKT.Windows;
