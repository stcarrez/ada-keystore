-----------------------------------------------------------------------
--  akt-windows -- GtK Windows for Ada Keystore GTK application
--  Copyright (C) 2019, 2020 Stephane Carrez
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
with Ada.IO_Exceptions;
with Ada.Exceptions;
with Ada.Calendar.Formatting;
with Interfaces;

with Glib.Error;
with Glib.Unicode;
with Glib.Object;

with Gtk.Main;
with Gtk.Label;
with Gtk.Enums;
with Gtk.Tree_View_Column;
with Gtk.Text_Iter;
with Gtk.Tool_Item;

with AKT.Callbacks;
package body AKT.Windows is

   use Ada.Strings.Unbounded;
   use type Glib.Gint;
   use type Gtk.Tree_View.Gtk_Tree_View;
   use type Gtk.Widget.Gtk_Widget;
   use type Interfaces.Unsigned_64;

   --  ------------------------------
   --  Initialize the target instance.
   --  ------------------------------
   overriding
   procedure Initialize (Application : in out Application_Type) is
   begin
      null;
   end Initialize;

   --  ------------------------------
   --  Release the storage.
   --  ------------------------------
   overriding
   procedure Finalize (Application : in out Application_Type) is
      use type Gtk.Widget.Gtk_Widget;
   begin
      if Application.Main /= null then
         Application.Main.Destroy;
         Application.About.Destroy;
         --  Application.Chooser.Destroy;
      end if;
   end Finalize;

   --  Load the glade XML definition.
   procedure Load_UI (Application : in out Application_Type) is separate;

   --  ------------------------------
   --  Initialize the widgets and create the Gtk gui.
   --  ------------------------------
   procedure Initialize_Widget (Application : in out Application_Type;
                                Widget : out Gtk.Widget.Gtk_Widget) is
      Timeline : Gtk.Widget.Gtk_Widget;
      Scrolled : Gtk.Scrolled_Window.Gtk_Scrolled_Window;
      Status   : Gtk.Status_Bar.Gtk_Status_Bar;
   begin
      Gtk.Main.Init;
      Gtkada.Builder.Gtk_New (Application.Builder);
      Load_UI (Application);
      AKT.Callbacks.Initialize (Application'Unchecked_Access, Application.Builder);
      Application.Builder.Do_Connect;
      Widget := Gtk.Widget.Gtk_Widget (Application.Builder.Get_Object ("main"));
      Application.Main := Widget;
      Application.About := Gtk.Widget.Gtk_Widget (Application.Builder.Get_Object ("about"));
      Application.Chooser
        := Gtk.Widget.Gtk_Widget (Application.Builder.Get_Object ("filechooser"));

      Timeline := Gtk.Widget.Gtk_Widget (Application.Builder.Get_Object ("scrolledView"));
      Scrolled := Gtk.Scrolled_Window.Gtk_Scrolled_Window (Timeline);
      Timeline := Gtk.Widget.Gtk_Widget (Application.Builder.Get_Object ("viewport1"));
      Application.Viewport := Gtk.Viewport.Gtk_Viewport (Timeline);

      Status := Gtk.Status_Bar.Gtk_Status_Bar (Application.Builder.Get_Object ("statusbar"));
      Application.Status := Status;

      Application.Scrolled := Scrolled;
      Gtk.Cell_Renderer_Text.Gtk_New (Application.Col_Text);
      Application.Scrolled.Set_Policy (Gtk.Enums.Policy_Always, Gtk.Enums.Policy_Always);
      Application.Col_Text.Ref;

      Application.Main.Show_All;
   end Initialize_Widget;

   procedure Open_File (Application : in out Application_Type;
                        Path        : in String;
                        Password    : in Keystore.Secret_Key) is
      use type Keystore.Header_Slot_Count_Type;

      procedure Process (Provider : in out Keystore.Passwords.Provider'Class);

      procedure Process (Provider : in out Keystore.Passwords.Provider'Class) is
      begin
         Application.Wallet.Unlock (Provider, Application.Slot);
      end Process;
   begin
      --  Close the current wallet if necessary.
      if Application.Wallet.Is_Open then
         Application.Wallet.Close;
      end if;

      Application.Path := To_Unbounded_String (Path);
      Application.Message ("Loading " & Path);
      Application.Wallet.Open (Path      => Path,
                               Config    => Application.Config,
                               Info      => Application.Info);
      if Application.Info.Header_Count = 0 then
         Keystore.Passwords.To_Provider (Password, Process'Access);
      else
         Application.GPG.Load_Secrets (Application.Wallet);

         Application.Wallet.Set_Master_Key (Application.GPG);

         Application.Wallet.Unlock (Application.GPG, Application.Slot);
      end if;
      Application.Locked := False;
      Application.Refresh_Toolbar;

      Application.Message ("Opened " & Path);

      Application.List_Keystore;
   exception
      when Keystore.Bad_Password =>
         Application.Message ("Invalid password to open " & Path);

      when Keystore.Corrupted | Keystore.Invalid_Storage | Keystore.Invalid_Block =>
         Application.Message ("File is corrupted");

      when Keystore.Invalid_Keystore | Ada.IO_Exceptions.End_Error =>
         Application.Message ("File is not a keystore");

      when E : others =>
         Application.Message ("Internal error: "
                              & Ada.Exceptions.Exception_Message (E));

   end Open_File;

   procedure Create_File (Application   : in out Application_Type;
                          Path          : in String;
                          Storage_Count : in Natural;
                          Password      : in Keystore.Secret_Key) is
      Config : Keystore.Wallet_Config := Keystore.Secure_Config;
   begin
      Config.Overwrite := True;
      if Storage_Count > 0 then
         Config.Storage_Count := Storage_Count;
      end if;

      --  Close the current wallet if necessary.
      if Application.Wallet.Is_Open then
         Application.Wallet.Close;
      end if;

      Application.Path := To_Unbounded_String (Path);
      Application.Message ("Creating " & Path);
      Keystore.Files.Create (Container => Application.Wallet,
                             Path      => Path,
                             Password  => Password,
                             Config    => Config,
                             Data_Path => "");
      Application.Locked := False;
      Application.Refresh_Toolbar;

      Application.Message ("Created " & Path);

      Application.List_Keystore;
   exception
      when Keystore.Invalid_Keystore | Ada.IO_Exceptions.End_Error =>
         Application.Message ("File is not a keystore");

      when E : others =>
         Log.Error ("Exception", E, True);
         Application.Message ("Internal error");

   end Create_File;

   procedure List_Keystore (Application : in out Application_Type) is

      procedure Add_Column (Name : in String; Column_Id : in Glib.Gint);
      procedure Set_Content (Name : in String);

      List  : Keystore.Entry_Map;
      Iter  : Keystore.Entry_Cursor;
      Types : constant Glib.GType_Array (0 .. 5) := (others => Glib.GType_String);

      procedure Add_Column (Name : in String; Column_Id : in Glib.Gint) is
         Col : Gtk.Tree_View_Column.Gtk_Tree_View_Column;
         Num : Glib.Gint;
         pragma Unreferenced (Num);
      begin
         Gtk.Tree_View_Column.Gtk_New (Col);
         Num := Application.Tree.Append_Column (Col);
         Col.Set_Sort_Column_Id (Column_Id - 1);
         Col.Set_Title (Name);
         Col.Pack_Start (Application.Col_Text, True);
         Col.Set_Sizing (Gtk.Tree_View_Column.Tree_View_Column_Autosize);
         Col.Add_Attribute (Application.Col_Text, "text", Column_Id - 1);
      end Add_Column;

      procedure Set_Content (Name : in String) is
         Data  : constant String := Application.Wallet.Get (Name);
         Valid : Boolean;
         Pos   : Natural;
      begin
         Glib.Unicode.UTF8_Validate (Data, Valid, Pos);
         if Valid then
            Gtk.Tree_Store.Set (Application.List, Application.Current_Row, 5, Data);
         else
            Gtk.Tree_Store.Set (Application.List, Application.Current_Row, 5, "--");
         end if;
      end Set_Content;

   begin
      Gtk.Status_Bar.Remove_All (Application.Status, 1);

      --  <name> <type> <size> <date> <content>
      Application.Wallet.List (Content => List);

      Gtk.Tree_Store.Gtk_New (Application.List, Types);
      if Application.Tree /= null then
         Application.Tree.Destroy;
      end if;
      Gtk.Tree_View.Gtk_New (Application.Tree, Gtk.Tree_Store."+" (Application.List));
      Application.Selection := Gtk.Tree_View.Get_Selection (Application.Tree);
      Gtk.Tree_Selection.Set_Mode (Application.Selection, Gtk.Enums.Selection_Single);

      Add_Column ("Date", 1);
      Add_Column ("Type", 2);
      Add_Column ("Size", 3);
      Add_Column ("Keys", 4);
      Add_Column ("Name", 5);
      Add_Column ("Content", 6);

      if Application.Editing then
         Application.Viewport.Remove (Application.Editor);
         Application.Editing := False;
      end if;
      Application.Viewport.Add (Application.Tree);

      Iter := List.First;
      while Keystore.Entry_Maps.Has_Element (Iter) loop
         declare
            Name : constant String := Keystore.Entry_Maps.Key (Iter);
            Item : constant Keystore.Entry_Info := Keystore.Entry_Maps.Element (Iter);
         begin
            Application.List.Append (Application.Current_Row, Gtk.Tree_Model.Null_Iter);

            if Application.Locked then
               Gtk.Tree_Store.Set (Application.List, Application.Current_Row,
                                   0, Ada.Calendar.Formatting.Image (Item.Create_Date));
               Gtk.Tree_Store.Set (Application.List, Application.Current_Row,
                                   1, Keystore.Entry_Type'Image (Item.Kind));
               Gtk.Tree_Store.Set (Application.List, Application.Current_Row,
                                   2, Interfaces.Unsigned_64'Image (Item.Size));
               Gtk.Tree_Store.Set (Application.List, Application.Current_Row,
                                   3, Natural'Image (Item.Block_Count));
               Gtk.Tree_Store.Set (Application.List, Application.Current_Row,
                                   4, "xxxxxxxx");
               Gtk.Tree_Store.Set (Application.List, Application.Current_Row,
                                   5, "XXXXXXXXXXX");
            else
               Gtk.Tree_Store.Set (Application.List, Application.Current_Row,
                                   0, Ada.Calendar.Formatting.Image (Item.Create_Date));
               Gtk.Tree_Store.Set (Application.List, Application.Current_Row,
                                   1, Keystore.Entry_Type'Image (Item.Kind));
               Gtk.Tree_Store.Set (Application.List, Application.Current_Row,
                                   2, Interfaces.Unsigned_64'Image (Item.Size));
               Gtk.Tree_Store.Set (Application.List, Application.Current_Row,
                                   3, Natural'Image (Item.Block_Count));
               Gtk.Tree_Store.Set (Application.List, Application.Current_Row,
                                   4, Name);
               if Item.Size < 1024 then
                  Set_Content (Name);
               else
                  Gtk.Tree_Store.Set (Application.List, Application.Current_Row,
                                      5, "--");
               end if;
            end if;
         end;
         Keystore.Entry_Maps.Next (Iter);
      end loop;

      Application.Scrolled.Show_All;
   end List_Keystore;

   procedure Edit_Value (Application : in out Application_Type;
                         Name        : in String) is
   begin
      declare
         Data  : constant String := Application.Wallet.Get (Name);
         Valid : Boolean;
         Pos   : Natural;
      begin
         Log.Info ("Selected {0}", Name);
         Glib.Unicode.UTF8_Validate (Data, Valid, Pos);
         if not Valid then
            Log.Warn ("Data is binary content and not valid UTF-8");
            Application.Message ("Cannot edit binary content");
            return;
         end if;
         Application.Current := Ada.Strings.Unbounded.To_Unbounded_String (Name);

         Gtk.Text_Buffer.Gtk_New (Application.Buffer);
         Gtk.Text_View.Gtk_New (Application.Editor, Application.Buffer);
         Gtk.Text_Buffer.Set_Text (Application.Buffer, Data);
         if not Application.Editing then
            Application.Viewport.Remove (Application.Tree);
            Application.Viewport.Add (Application.Editor);
            Application.Editor.Show_All;
            Application.Editing := True;
         end if;
      end;

   exception
      when Keystore.Not_Found =>
         Application.Message ("Value not found: " & Name);

      when E : others =>
         Log.Error ("Exception to edit content", E);
         Application.Message ("Cannot edit content");

   end Edit_Value;

   procedure Edit_Current (Application : in out Application_Type) is
      Model : Gtk.Tree_Model.Gtk_Tree_Model;
      Iter  : Gtk.Tree_Model.Gtk_Tree_Iter;
   begin
      Gtk.Status_Bar.Remove_All (Application.Status, 1);

      Gtk.Tree_Selection.Get_Selected (Selection => Application.Selection,
                                       Model     => Model,
                                       Iter      => Iter);
      declare
         Name  : constant String := Gtk.Tree_Model.Get_String (Model, Iter, 4);
      begin
         Application.Edit_Value (Name);
      end;
   end Edit_Current;

   procedure Save_Current (Application : in out Application_Type) is
      Start : Gtk.Text_Iter.Gtk_Text_Iter;
      Stop  : Gtk.Text_Iter.Gtk_Text_Iter;
   begin
      if Application.Editing then
         Gtk.Text_Buffer.Get_Bounds (Application.Buffer, Start, Stop);
         Application.Wallet.Set (Ada.Strings.Unbounded.To_String (Application.Current),
                                 Gtk.Text_Buffer.Get_Text (Application.Buffer, Start, Stop));
         Application.List_Keystore;
      end if;
   end Save_Current;

   --  ------------------------------
   --  Lock the keystore so that it is necessary to ask the password again to see/edit items.
   --  ------------------------------
   procedure Lock (Application : in out Application_Type) is
   begin
      Application.Locked := True;
      if Application.Wallet.Is_Open then
         Application.List_Keystore;
         Application.Wallet.Close;
      end if;
      Application.Refresh_Toolbar;
   end Lock;

   --  ------------------------------
   --  Unlock the keystore with the password.
   --  ------------------------------
   procedure Unlock (Application : in out Application_Type;
                     Password    : in Keystore.Secret_Key) is
   begin
      if Application.Locked then
         Application.Open_File (Path     => To_String (Application.Path),
                                Password => Password);
      end if;
   end Unlock;

   --  ------------------------------
   --  Return True if the keystore is locked.
   --  ------------------------------
   function Is_Locked (Application : in Application_Type) return Boolean is
   begin
      return Application.Locked;
   end Is_Locked;

   --  ------------------------------
   --  Return True if the keystore is open.
   --  ------------------------------
   function Is_Open (Application : in Application_Type) return Boolean is
   begin
      return Application.Wallet.Is_Open;
   end Is_Open;

   --  ------------------------------
   --  Set the UI label with the given value.
   --  ------------------------------
   procedure Set_Label (Application : in Application_Type;
                        Name   : in String;
                        Value  : in String) is
      use type Glib.Object.GObject;

      Object : constant Glib.Object.GObject := Application.Builder.Get_Object (Name);
      Label  : Gtk.Label.Gtk_Label;
   begin
      if Object /= null then
         Label := Gtk.Label.Gtk_Label (Object);
         Label.Set_Label (Value);
      end if;
   end Set_Label;

   --  ------------------------------
   --  Report a message in the status area.
   --  ------------------------------
   procedure Message (Application : in out Application_Type;
                      Message     : in String) is
      Msg : Gtk.Status_Bar.Message_Id with Unreferenced;
   begin
      Msg := Gtk.Status_Bar.Push (Application.Status, 1, Message);
   end Message;

   procedure Refresh_Toolbar (Application : in out Application_Type) is
      Unlock_Button : constant Gtk.Widget.Gtk_Widget
        := Gtk.Widget.Gtk_Widget (Application.Builder.Get_Object ("tool_unlock_button"));
      Lock_Button : constant Gtk.Widget.Gtk_Widget
        := Gtk.Widget.Gtk_Widget (Application.Builder.Get_Object ("tool_lock_button"));
      Edit_Button : constant Gtk.Widget.Gtk_Widget
        := Gtk.Widget.Gtk_Widget (Application.Builder.Get_Object ("tool_edit_button"));
      Save_Button : constant Gtk.Widget.Gtk_Widget
        := Gtk.Widget.Gtk_Widget (Application.Builder.Get_Object ("tool_save_button"));
      Item : Gtk.Tool_Item.Gtk_Tool_Item;
   begin
      if Lock_Button /= null then
         Item := Gtk.Tool_Item.Gtk_Tool_Item (Lock_Button);
         Item.Set_Visible_Horizontal (not Application.Is_Locked and Application.Is_Open);
      end if;
      if Unlock_Button /= null then
         Item := Gtk.Tool_Item.Gtk_Tool_Item (Unlock_Button);
         Item.Set_Visible_Horizontal (Application.Is_Locked);
      end if;
      if Edit_Button /= null then
         Item := Gtk.Tool_Item.Gtk_Tool_Item (Edit_Button);
         Item.Set_Visible_Horizontal (Application.Is_Open and not Application.Editing);
      end if;
      if Save_Button /= null then
         Item := Gtk.Tool_Item.Gtk_Tool_Item (Save_Button);
         Item.Set_Visible_Horizontal (Application.Is_Open and Application.Editing);
      end if;
   end Refresh_Toolbar;

   procedure Main (Application : in out Application_Type) is
      pragma Unreferenced (Application);
   begin
      Gtk.Main.Main;
   end Main;

end AKT.Windows;
