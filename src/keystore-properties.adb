-----------------------------------------------------------------------
--  keystore-properties -- Property manager on top of keystore
--  Copyright (C) 2020, 2022 Stephane Carrez
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

with Util.Beans.Objects;
package body Keystore.Properties is

   type Wallet_Manager is limited new Util.Properties.Implementation.Manager with record
      Wallet : Wallet_File_Access;
      Props  : Util.Properties.Manager;
   end record;
   type Keystore_Manager_Access is access all Wallet_Manager'Class;

   --  Get the value identified by the name.
   --  If the name cannot be found, the method should return the Null object.
   overriding
   function Get_Value (From : in Wallet_Manager;
                       Name : in String) return Util.Beans.Objects.Object;

   --  Set the value identified by the name.
   --  If the map contains the given name, the value changed.
   --  Otherwise name is added to the map and the value associated with it.
   overriding
   procedure Set_Value (From  : in out Wallet_Manager;
                        Name  : in String;
                        Value : in Util.Beans.Objects.Object);

   --  Returns TRUE if the property exists.
   overriding
   function Exists (Self : in Wallet_Manager;
                    Name : in String)
                    return Boolean;

   --  Remove the property given its name.
   overriding
   procedure Remove (Self : in out Wallet_Manager;
                     Name : in String);

   --  Iterate over the properties and execute the given procedure passing the
   --  property name and its value.
   overriding
   procedure Iterate (Self    : in Wallet_Manager;
                      Process : access procedure (Name : in String;
                                                  Item : in Util.Beans.Objects.Object));

   --  Deep copy of properties stored in 'From' to 'To'.
   overriding
   function Create_Copy (Self : in Wallet_Manager)
                         return Util.Properties.Implementation.Manager_Access;

   package Shared_Manager is
     new Util.Properties.Implementation.Shared_Implementation (Wallet_Manager);

   subtype Property_Map is Shared_Manager.Manager;
   type Property_Map_Access is access all Property_Map;

   function Allocate_Property return Util.Properties.Implementation.Shared_Manager_Access is
     (new Property_Map);

   --  Create a property implementation if there is none yet.
   procedure Check_And_Create_Impl is
      new Util.Properties.Implementation.Create (Allocator => Allocate_Property);

   overriding
   procedure Initialize (Object : in out Manager) is
   begin
      Check_And_Create_Impl (Object);
   end Initialize;

   --  ------------------------------
   --  Get the value identified by the name.
   --  If the name cannot be found, the method should return the Null object.
   --  ------------------------------
   overriding
   function Get_Value (From : in Wallet_Manager;
                       Name : in String) return Util.Beans.Objects.Object is
   begin
      if From.Wallet.Contains (Name) then
         declare
            Value : constant String := From.Wallet.Get (Name);
         begin
            return Util.Beans.Objects.To_Object (Value);
         end;
      else
         return Util.Beans.Objects.Null_Object;
      end if;

   exception
      when Not_Found =>
         return Util.Beans.Objects.Null_Object;
   end Get_Value;

   --  ------------------------------
   --  Set the value identified by the name.
   --  If the map contains the given name, the value changed.
   --  Otherwise name is added to the map and the value associated with it.
   --  ------------------------------
   overriding
   procedure Set_Value (From  : in out Wallet_Manager;
                        Name  : in String;
                        Value : in Util.Beans.Objects.Object) is
   begin
      From.Wallet.Set (Name, Util.Beans.Objects.To_String (Value));
   end Set_Value;

   --  ------------------------------
   --  Returns TRUE if the property exists.
   --  ------------------------------
   overriding
   function Exists (Self : in Wallet_Manager;
                    Name : in String)
                    return Boolean is
   begin
      return Self.Wallet.Contains (Name);
   end Exists;

   --  ------------------------------
   --  Remove the property given its name.
   --  ------------------------------
   overriding
   procedure Remove (Self : in out Wallet_Manager;
                     Name : in String) is
   begin
      if Self.Wallet.Contains (Name) then
         Self.Wallet.Delete (Name);
      end if;
   end Remove;

   --  ------------------------------
   --  Iterate over the properties and execute the given procedure passing the
   --  property name and its value.
   --  ------------------------------
   overriding
   procedure Iterate (Self    : in Wallet_Manager;
                      Process : access procedure (Name : in String;
                                                  Item : in Util.Beans.Objects.Object)) is
      List  : Keystore.Entry_Map;
      Iter  : Keystore.Entry_Cursor;
   begin
      Self.Wallet.List (Filter => (T_STRING => True, others => False), Content => List);
      Iter := List.First;
      while Keystore.Entry_Maps.Has_Element (Iter) loop
         declare
            Name  : constant String := Keystore.Entry_Maps.Key (Iter);
            Value : constant String := Self.Wallet.Get (Name);
         begin
            Process (Name, Util.Beans.Objects.To_Object (Value));
         end;
         Keystore.Entry_Maps.Next (Iter);
      end loop;
   end Iterate;

   --  ------------------------------
   --  Deep copy of properties stored in 'From' to 'To'.
   --  ------------------------------
   overriding
   function Create_Copy (Self : in Wallet_Manager)
                         return Util.Properties.Implementation.Manager_Access is
      Result : constant Keystore_Manager_Access := new Property_Map;
   begin
      Result.Wallet := Self.Wallet;
      Result.Props := Self.Props;
      return Result.all'Access;
   end Create_Copy;

   procedure Initialize (Props  : in out Manager'Class;
                         Wallet : in Wallet_File_Access) is
      function Allocate return Util.Properties.Implementation.Shared_Manager_Access;

      function Allocate return Util.Properties.Implementation.Shared_Manager_Access is
         Impl : constant Property_Map_Access := new Property_Map;
      begin
         Impl.Wallet := Wallet;
         return Impl.all'Access;
      end Allocate;

      procedure Setup is
        new Util.Properties.Implementation.Initialize (Allocate);

   begin
      Setup (Props);
   end Initialize;

end Keystore.Properties;
