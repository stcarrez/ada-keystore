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
with Ada.IO_Exceptions;
with Ada.Exceptions;
with Ada.Calendar.Formatting;

with Glib.Error;
with Glib.Object;

with Gtk.Main;
with Gtk.Label;
with Gtk.Frame;
with Gtk.Enums;
with Gtk.Scrolled_Window;
with Gtk.Viewport;
with Gtk.Tree_View_Column;

with AKT.Callbacks;
package body AKT.Windows is

   use type Glib.Gint;
   use type Gtk.Tree_View.Gtk_Tree_View;

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
      Error    : aliased Glib.Error.GError;
      Result   : Glib.Guint;
      Timeline : Gtk.Widget.Gtk_Widget;
      Scrolled : Gtk.Scrolled_Window.Gtk_Scrolled_Window;
      Viewport : Gtk.Viewport.Gtk_Viewport;
      Status   : Gtk.Status_Bar.Gtk_Status_Bar;
   begin
      Gtk.Main.Init;
      Gtkada.Builder.Gtk_New (Application.Builder);
      --           Result := Target.Builder.Add_From_File ("gatk.glade", Error'Access);
      Load_UI (Application);
      AKT.Callbacks.Initialize (Application'Unchecked_Access, Application.Builder);
      Application.Builder.Do_Connect;
      Widget := Gtk.Widget.Gtk_Widget (Application.Builder.Get_Object ("main"));
      Application.Main := Widget;
      Application.About := Gtk.Widget.Gtk_Widget (Application.Builder.Get_Object ("about"));
      Application.Chooser := Gtk.Widget.Gtk_Widget (Application.Builder.Get_Object ("filechooser"));

      Timeline := Gtk.Widget.Gtk_Widget (Application.Builder.Get_Object ("scrolledView"));
      Scrolled := Gtk.Scrolled_Window.Gtk_Scrolled_Window (Timeline);
      Timeline := Gtk.Widget.Gtk_Widget (Application.Builder.Get_Object ("viewport1"));
      Application.Viewport := Gtk.Viewport.Gtk_Viewport (Timeline);

      Status := Gtk.Status_Bar.Gtk_Status_Bar (Application.Builder.Get_Object ("statusbar"));
      Application.Status := Status;

      Application.Scrolled := Scrolled; --  Gtk.Scrolled_Window.Gtk_New (Application.Scrolled);
      Gtk.Cell_Renderer_Text.Gtk_New (Application.Col_Text);
      Application.Scrolled.Set_Policy (Gtk.Enums.Policy_Always, Gtk.Enums.Policy_Always);
      --  Console.Frame := Frame;
      --  Console.Frame.Add (Console.Scrolled);
      Application.Col_Text.Ref;

      --  Viewport.Add (Application.Events.Drawing);
      Application.Main.Show_All;
   end Initialize_Widget;

   procedure Open_File (Application : in out Application_Type;
                        Path        : in String;
                        Password    : in Keystore.Secret_Key) is
      Msg : Gtk.Status_Bar.Message_Id;
   begin
      Msg := Gtk.Status_Bar.Push (Application.Status, 1, "Loading " & Path);
      Application.Wallet.Open (Path => Path, Password => Password);

      Msg := Gtk.Status_Bar.Push (Application.Status, 1, "Opened " & Path);

      Application.List_Keystore;
   exception
      when Keystore.Bad_Password =>
         Msg := Gtk.Status_Bar.Push (Application.Status, 1, "Invalid password to open " & Path);

      when Keystore.Corrupted =>
         Msg := Gtk.Status_Bar.Push (Application.Status, 1, "File is corrupted");

      when Ada.IO_Exceptions.End_Error =>
         Msg := Gtk.Status_Bar.Push (Application.Status, 1, "File is not a keystore");

      when E : others =>
         Msg := Gtk.Status_Bar.Push (Application.Status, 1, "Internal error: "
                                     & Ada.Exceptions.Exception_Message (E));

   end Open_File;

   procedure List_Keystore (Application : in out Application_Type) is
      List  : Keystore.Entry_Map;
      Iter  : Keystore.Entry_Cursor;
      Types : Glib.GType_Array (0 .. 4) := (others => Glib.GType_String);

      procedure Add_Column (Name : in String; Column_Id : in Glib.Gint) is
         Col : Gtk.Tree_View_Column.Gtk_Tree_View_Column;
         Num : Glib.Gint;
      begin
         Gtk.Tree_View_Column.Gtk_New (Col);
         Num := Application.Tree.Append_Column (Col);
         Col.Set_Sort_Column_Id (Column_Id - 1);
         Col.Set_Title (Name);
         Col.Pack_Start (Application.Col_Text, True);
         Col.Set_Sizing (Gtk.Tree_View_Column.Tree_View_Column_Autosize);
         Col.Add_Attribute (Application.Col_Text, "text", Column_Id - 1);
      end Add_Column;

   begin
      -- <name> <type> <size> <date> <content>
      Application.Wallet.List (List);

      Gtk.Tree_Store.Gtk_New (Application.List, Types);
      if Application.Tree /= null then
         Application.Tree.Destroy;
      end if;
      Gtk.Tree_View.Gtk_New (Application.Tree, Gtk.Tree_Store."+" (Application.List));

      Add_Column ("Name", 1);
      Add_Column ("Type", 2);
      Add_Column ("Size", 3);
      Add_Column ("Date", 4);
      Add_Column ("Content", 5);
      Application.Viewport.Add (Application.Tree);

      Iter := List.First;
      while Keystore.Entry_Maps.Has_Element (Iter) loop
         declare
            Name : constant String := Keystore.Entry_Maps.Key (Iter);
            Item : constant Keystore.Entry_Info := Keystore.Entry_Maps.Element (Iter);
         begin
            Application.List.Append (Application.Current_Row, Gtk.Tree_Model.Null_Iter);

            Gtk.Tree_Store.Set (Application.List, Application.Current_Row,
                                0, Name);
            Gtk.Tree_Store.Set (Application.List, Application.Current_Row,
                                1, Keystore.Entry_Type'Image (Item.Kind));
            Gtk.Tree_Store.Set (Application.List, Application.Current_Row,
                                2, Natural'Image (Item.Size));
            Gtk.Tree_Store.Set (Application.List, Application.Current_Row,
                                3, Ada.Calendar.Formatting.Image (Item.Create_Date));
            if Item.Size < 1024 then
               Gtk.Tree_Store.Set (Application.List, Application.Current_Row,
                                   4, Application.Wallet.Get (Name));
            end if;
         end;
         Keystore.Entry_Maps.Next (Iter);
      end loop;

      Application.Scrolled.Show_All;
   end List_Keystore;

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

   procedure Main (Application : in out Application_Type) is
   begin
      Gtk.Main.Main;
   end Main;

end AKT.Windows;
