-----------------------------------------------------------------------
--  keystore-tools -- Tools for the keystore
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
with Ada.Streams.Stream_IO;
with Util.Log.Loggers;
with Util.Streams.Files;

package body Keystore.Tools is

   use type Ada.Directories.File_Kind;

   subtype File_Kind is Ada.Directories.File_Kind;

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Keystore.Tools");

   --  ------------------------------
   --  Store the file in the keystore and use the prefix followed by the file basename
   --  for the name to identify the stored the content.
   --  ------------------------------
   procedure Store (Wallet  : in out Keystore.Wallet'Class;
                    Path    : in String;
                    Prefix  : in String) is
      Name  : constant String := Prefix & Ada.Directories.Simple_Name (Path);
      File  : Util.Streams.Files.File_Stream;
   begin
      Log.Info ("Store file {0} as {1}", Path, Name);

      File.Open (Mode => Ada.Streams.Stream_IO.In_File,
                 Name => Path);

      Wallet.Set (Name  => Name,
                  Kind  => Keystore.T_FILE,
                  Input => File);
   end Store;

   --  ------------------------------
   --  Scan the directory for files matching the pattern and store them in the
   --  keystore when the filter predicate accepts them.
   --  ------------------------------
   procedure Store (Wallet  : in out Keystore.Wallet'Class;
                    Path    : in String;
                    Prefix  : in String;
                    Pattern : in String;
                    Filter  : not null
                    access function (Ent : in Directory_Entry_Type) return Boolean) is
      Search_Filter : constant Ada.Directories.Filter_Type
        := (Ada.Directories.Ordinary_File => True,
            Ada.Directories.Directory     => True,
            Ada.Directories.Special_File  => False);
      Search   : Ada.Directories.Search_Type;
      Ent      : Directory_Entry_Type;
   begin
      Log.Info ("Scan directory {0}", Path);

      Ada.Directories.Start_Search (Search, Directory => Path,
                                    Pattern => Pattern, Filter => Search_Filter);
      while Ada.Directories.More_Entries (Search) loop
         Ada.Directories.Get_Next_Entry (Search, Ent);
         declare
            Name  : constant String    := Ada.Directories.Simple_Name (Ent);
            Kind  : constant File_Kind := Ada.Directories.Kind (Ent);
            Fpath : constant String    := Ada.Directories.Full_Name (Ent);
         begin
            if Kind /= Ada.Directories.Directory then
               if Filter (Ent) then
                  Store (Wallet, Fpath, Prefix);
               end if;
            elsif Name /= "." and then Name /= ".." then
               if Filter (Ent) then
                  Store (Wallet, Fpath, Prefix & Name & '/', Pattern, Filter);
               end if;
            end if;
         end;
      end loop;
   end Store;

end Keystore.Tools;
