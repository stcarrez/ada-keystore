-----------------------------------------------------------------------
--  akt-commands-list -- List content of keystore
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
with Ada.Text_IO;
with Util.Dates.ISO8601;
package body AKT.Commands.List is

   --  ------------------------------
   --  List the value entries of the keystore.
   --  ------------------------------
   overriding
   procedure Execute (Command   : in out Command_Type;
                      Name      : in String;
                      Args      : in Argument_List'Class;
                      Context   : in out Context_Type) is
      List : Keystore.Entry_Map;
      Iter : Keystore.Entry_Cursor;
   begin
      Context.Open_Keystore;
      Context.Wallet.List (List);
      Iter := List.First;
      while Keystore.Entry_Maps.Has_Element (Iter) loop
         declare
            Name : constant String := Keystore.Entry_Maps.Key (Iter);
            Item : constant Keystore.Entry_Info := Keystore.Entry_Maps.Element (Iter);
         begin
            if Name'Length > 60 then
               Ada.Text_IO.Put (Name (Name'First .. Name'First + 60));
            else
               Ada.Text_IO.Put (Name);
            end if;
            Ada.Text_IO.Set_Col (63);
            Ada.Text_IO.Put (Integer'Image (Item.Size));
            Ada.Text_IO.Put (Util.Dates.ISO8601.Image (Item.Create_Date, Util.Dates.ISO8601.MINUTE));
            Ada.Text_IO.New_Line;
         end;
         Keystore.Entry_Maps.Next (Iter);
      end loop;
   end Execute;

   --  ------------------------------
   --  Write the help associated with the command.
   --  ------------------------------
   overriding
   procedure Help (Command   : in out Command_Type;
                   Context   : in out Context_Type) is
   begin
      Ada.Text_IO.Put_Line ("set: insert a new value in the keystore");
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("Usage: set <name> <value>");
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("  ");
   end Help;

end AKT.Commands.List;
