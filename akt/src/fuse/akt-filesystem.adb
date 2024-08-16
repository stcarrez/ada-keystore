-----------------------------------------------------------------------
--  akt-filesystem -- Fuse filesystem operations
--  Copyright (C) 2019, 2020, 2022 Stephane Carrez
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
with Ada.Calendar.Conversions;

with Util.Strings;
with Util.Log.Loggers;
package body AKT.Filesystem is

   use type System.St_Mode_Type;
   use type Interfaces.Unsigned_64;
   use type Keystore.Entry_Type;
   use Ada.Streams;

   Log     : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("AKT.Filesystem");

   pragma Linker_Options ("-lfuse");

   procedure Initialize (St_Buf : access System.Stat_Type;
                         Mode   : in System.St_Mode_Type);

   function To_Unix (Date : in Ada.Calendar.Time) return Interfaces.Integer_64 is
      (Interfaces.Integer_64 (Ada.Calendar.Conversions.To_Unix_Time (Date)));

   procedure Initialize (St_Buf : access System.Stat_Type;
                         Mode   : in System.St_Mode_Type) is
   begin
      St_Buf.St_Dev := 0;
      St_Buf.St_Ino := 0;
      St_Buf.St_Nlink := 1;
      St_Buf.St_Uid := 0;
      St_Buf.St_Gid := 0;
      St_Buf.St_Rdev := 0;
      St_Buf.St_Size := 0;
      St_Buf.St_Atime := 0;
      St_Buf.St_Mtime := 0;
      St_Buf.St_Ctime := 0;
      St_Buf.St_Blksize := 8192;
      St_Buf.St_Blocks := 0;
      St_Buf.St_Mode := System.Mode_T_to_St_Mode (8#700#) or Mode;
   end Initialize;

   --------------------------
   --    Get Attributes    --
   --------------------------
   function GetAttr (Path   : in String;
                     St_Buf : access System.Stat_Type) return System.Error_Type is
      Data   : constant User_Data_Type := General.Get_User_Data;
      Info   : Keystore.Entry_Info;
   begin
      Log.Debug ("Get attributes of {0}", Path);

      if Path'Length = 0 then
         return System.ENOENT;
      elsif Path = "/" then
         Initialize (St_Buf, System.S_IFDIR);
      else
         Initialize (St_Buf, System.S_IFREG);

         Info := Data.Wallet.Find (Path (Path'First + 1 .. Path'Last));

         if Info.Kind = Keystore.T_DIRECTORY then
            St_Buf.St_Mode := System.Mode_T_to_St_Mode (8#700#);
            St_Buf.St_Mode := St_Buf.St_Mode or System.S_IFDIR;
         else
            St_Buf.St_Mode := System.Mode_T_to_St_Mode (8#600#);
            St_Buf.St_Mode := St_Buf.St_Mode or System.S_IFREG;
         end if;
         St_Buf.St_Size := Interfaces.Integer_64 (Info.Size);
         St_Buf.St_Ctime := To_Unix (Info.Create_Date);
         St_Buf.St_Mtime := To_Unix (Info.Update_Date);
         St_Buf.St_Atime := St_Buf.St_Mtime;
      end if;

      return System.EXIT_SUCCESS;

   exception
      when Keystore.Not_Found =>
         return System.ENOENT;

   end GetAttr;

   --------------------------
   --         MkDir        --
   --------------------------
   function MkDir (Path   : in String;
                   Mode   : in System.St_Mode_Type) return System.Error_Type is
      pragma Unreferenced (Mode);

      Data   : constant User_Data_Type := General.Get_User_Data;
      Empty  : constant Ada.Streams.Stream_Element_Array (1 .. 0) := (others => <>);
   begin
      Log.Info ("Mkdir {0}", Path);

      Data.Wallet.Add (Name => Path (Path'First + 1 .. Path'Last),
                       Kind => Keystore.T_DIRECTORY,
                       Content => Empty);
      return System.EXIT_SUCCESS;

   exception
      when Keystore.Name_Exist =>
         return System.EEXIST;

   end MkDir;

   --------------------------
   --         Unlink       --
   --------------------------
   function Unlink (Path   : in String) return System.Error_Type is
      Data   : constant User_Data_Type := General.Get_User_Data;
   begin
      Log.Info ("Unlink {0}", Path);

      Data.Wallet.Delete (Name => Path (Path'First + 1 .. Path'Last));
      return System.EXIT_SUCCESS;

   exception
      when Keystore.Not_Found =>
         return System.ENOENT;

   end Unlink;

   --------------------------
   --          RmDir       --
   --------------------------
   function RmDir (Path   : in String) return System.Error_Type is
      Data   : constant User_Data_Type := General.Get_User_Data;
   begin
      Log.Info ("Rmdir {0}", Path);

      declare
         Item : constant Keystore.Entry_Info
           := Data.Wallet.Find (Path (Path'First + 1 .. Path'Last));
      begin
         if Item.Kind /= Keystore.T_DIRECTORY then
            return System.ENOTDIR;
         end if;

         Data.Wallet.Delete (Path (Path'First + 1 .. Path'Last));
         return System.EXIT_SUCCESS;
      end;

   exception
      when Keystore.Not_Found =>
         return System.ENOENT;

   end RmDir;

   --------------------------
   --        Create        --
   --------------------------
   function Create (Path   : in String;
                    Mode   : in System.St_Mode_Type;
                    Fi     : access System.File_Info_Type) return System.Error_Type is
      pragma Unreferenced (Mode);

      Data   : constant User_Data_Type := General.Get_User_Data;
   begin
      Log.Info ("Create {0}", Path);

      Fi.Direct_IO := Data.Direct_IO;
      Fi.Keep_Cache := not Data.Direct_IO;
      Data.Wallet.Add (Path (Path'First + 1 .. Path'Last), "");
      return System.EXIT_SUCCESS;

   exception
      when Keystore.Name_Exist =>
         return System.EEXIST;
   end Create;

   --------------------------
   --         Open         --
   --------------------------
   function Open (Path   : in String;
                  Fi     : access System.File_Info_Type) return System.Error_Type is
      Data   : constant User_Data_Type := General.Get_User_Data;
   begin
      Log.Info ("Open {0}", Path);

      Fi.Direct_IO := Data.Direct_IO;
      Fi.Keep_Cache := not Data.Direct_IO;
      if not Data.Wallet.Contains (Path (Path'First + 1 .. Path'Last)) then
         return System.ENOENT;
      else
         return System.EXIT_SUCCESS;
      end if;
   end Open;

   --------------------------
   --        Release       --
   --------------------------
   function Release (Path   : in String;
                     Fi     : access System.File_Info_Type) return System.Error_Type is
      pragma Unreferenced (Fi);
   begin
      Log.Info ("Release {0}", Path);

      return System.EXIT_SUCCESS;
   end Release;

   --------------------------
   --          Read        --
   --------------------------
   function Read (Path   : in String;
                  Buffer : access Buffer_Type;
                  Size   : in out Natural;
                  Offset : in Natural;
                  Fi     : access System.File_Info_Type) return System.Error_Type is
      Data   : constant User_Data_Type := General.Get_User_Data;
      Last   : Stream_Element_Offset;

      Buf    : Ada.Streams.Stream_Element_Array (1 .. Ada.Streams.Stream_Element_Offset (Size));
      for Buf'Address use Buffer.all'Address;

   begin
      Log.Info ("Read {0}", Path);

      Fi.Direct_IO := Data.Direct_IO;
      Fi.Keep_Cache := not Data.Direct_IO;
      Data.Wallet.Read (Name    => Path (Path'First + 1 .. Path'Last),
                        Offset  => Stream_Element_Offset (Offset),
                        Content => Buf,
                        Last    => Last);

      Size := Natural (Last - Buf'First + 1);
      return System.EXIT_SUCCESS;

   exception
      when Keystore.Not_Found =>
         return System.EINVAL;
   end Read;

   --------------------------
   --         Write        --
   --------------------------
   function Write (Path   : in String;
                   Buffer : access Buffer_Type;
                   Size   : in out Natural;
                   Offset : in Natural;
                   Fi     : access System.File_Info_Type) return System.Error_Type is
      pragma Unmodified (Size);

      Data   : constant User_Data_Type := General.Get_User_Data;

      Buf    : Ada.Streams.Stream_Element_Array (1 .. Ada.Streams.Stream_Element_Offset (Size));
      for Buf'Address use Buffer.all'Address;
   begin
      Log.Info ("Write {0} at {1}", Path,
                Natural'Image (Offset) & " size" & Natural'Image (Size));

      Fi.Direct_IO := Data.Direct_IO;
      Fi.Keep_Cache := not Data.Direct_IO;
      Data.Wallet.Write (Name    => Path (Path'First + 1 .. Path'Last),
                         Offset  => Stream_Element_Offset (Offset),
                         Content => Buf);

      return System.EXIT_SUCCESS;

   exception
      when Keystore.Not_Found =>
         return System.EINVAL;
   end Write;

   --------------------------
   --       Read Dir       --
   --------------------------
   function ReadDir (Path   : in String;
                     Filler : access procedure (Name     : String;
                                                St_Buf   : System.Stat_Access;
                                                Offset   : Natural);
                     Offset : in Natural;
                     Fi     : access System.File_Info_Type) return System.Error_Type is
      pragma Unreferenced (Offset, Fi);

      Data    : constant User_Data_Type := General.Get_User_Data;
      List    : Keystore.Entry_Map;
      Iter    : Keystore.Entry_Cursor;
      St_Buf  : aliased System.Stat_Type;
   begin
      Log.Info ("Read directory {0}", Path);

      Initialize (St_Buf'Unchecked_Access, System.S_IFDIR);
      St_Buf.St_Mode := (S_IFDIR => True, S_IRUSR => True, S_IWUSR => True, others => False);

      Data.Wallet.List (Content => List);
      Iter := List.First;
      St_Buf.St_Mode := (S_IFREG => True, S_IRUSR => True, S_IWUSR => True, others => False);
      while Keystore.Entry_Maps.Has_Element (Iter) loop
         declare
            Name  : constant String := Keystore.Entry_Maps.Key (Iter);
            Pos   : Natural := Util.Strings.Rindex (Name, '/');
         begin
            if Pos = 0 then
               Pos := Name'First - 1;
            end if;
            if Name (Name'First .. Pos - 1) = Path (Path'First + 1 .. Path'Last) then
               declare
                  Item : constant Keystore.Entry_Info := Keystore.Entry_Maps.Element (Iter);
               begin
                  if Item.Kind = Keystore.T_DIRECTORY then
                     Log.Info ("Directory {0}", Name);
                     Initialize (St_Buf'Unchecked_Access, System.S_IFDIR);
                  else
                     Initialize (St_Buf'Unchecked_Access, System.S_IFREG);
                     Log.Info ("Item {0}", Name);
                  end if;
                  St_Buf.St_Size := Interfaces.Integer_64 (Item.Size);
                  St_Buf.St_Ctime := To_Unix (Item.Create_Date);
                  St_Buf.St_Mtime := To_Unix (Item.Update_Date);
                  St_Buf.St_Blocks := Interfaces.Integer_64 (Item.Block_Count);
                  Filler.all (Name (Pos + 1 .. Name'Last), St_Buf'Unchecked_Access, 0);
               end;
            end if;
         end;
         Keystore.Entry_Maps.Next (Iter);
      end loop;

      return System.EXIT_SUCCESS;

   exception
      when Keystore.Not_Found =>
         return System.ENOENT;
   end ReadDir;

   function Truncate (Path   : in String;
                      Size   : in Natural)
                      return System.Error_Type is
      Data   : constant User_Data_Type := General.Get_User_Data;
   begin
      Log.Info ("Truncate {0} to {1}", Path, Natural'Image (Size));

      if Size /= 0 then
         return System.EPERM;
      end if;

      Data.Wallet.Set (Path (Path'First + 1 .. Path'Last), "");
      return System.EXIT_SUCCESS;
   end Truncate;

end AKT.Filesystem;
