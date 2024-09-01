-----------------------------------------------------------------------
--  akt-commands-list -- List content of keystore
--  Copyright (C) 2019, 2024 Stephane Carrez
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
with Interfaces;
with Ada.Calendar.Formatting;
package body AKT.Commands.List is

   --  ------------------------------
   --  List the value entries of the keystore.
   --  ------------------------------
   overriding
   procedure Execute (Command   : in out Command_Type;
                      Name      : in String;
                      Args      : in Argument_List'Class;
                      Context   : in out Context_Type) is
      pragma Unreferenced (Command, Name);
      use AKT.Commands.Consoles;

      List    : Keystore.Entry_Map;
      Iter    : Keystore.Entry_Cursor;
      Max_Len : Positive := 53;  --  Default name length
   begin
      Context.Open_Keystore (Args);
      Context.Wallet.List (Content => List);

      if List.Is_Empty then
         return;
      end if;

      --  Check if we have long names to print to avoid truncating them.
      Iter := List.First;
      while Keystore.Entry_Maps.Has_Element (Iter) loop
         declare
            Name : constant String := Keystore.Entry_Maps.Key (Iter);
         begin
            if Name'Length > Max_Len then
               Max_Len := Name'Length + 1;
            end if;
         end;
         Keystore.Entry_Maps.Next (Iter);
      end loop;

      Context.Console.Start_Title;
      Context.Console.Print_Title (1, -("Name"), Max_Len);
      Context.Console.Print_Title (2, -("Size"), 9, J_RIGHT);
      Context.Console.Print_Title (3, -("Block"), 7, J_RIGHT);
      Context.Console.Print_Title (4, -("Date"), 20);
      Context.Console.End_Title;

      Iter := List.First;
      while Keystore.Entry_Maps.Has_Element (Iter) loop
         declare
            Name : constant String := Keystore.Entry_Maps.Key (Iter);
            Item : constant Keystore.Entry_Info := Keystore.Entry_Maps.Element (Iter);
         begin
            Context.Console.Start_Row;
            Context.Console.Print_Field (1, Name);
            Context.Console.Print_Field (2, Interfaces.Unsigned_64'Image (Item.Size), J_RIGHT);
            Context.Console.Print_Field (3, Natural'Image (Item.Block_Count), J_RIGHT);
            Context.Console.Print_Field (4, Ada.Calendar.Formatting.Image (Item.Create_Date));
            Context.Console.End_Row;
         end;
         Keystore.Entry_Maps.Next (Iter);
      end loop;
   end Execute;

end AKT.Commands.List;
