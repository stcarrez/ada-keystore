-----------------------------------------------------------------------
--  keystore-io-files -- Ada keystore IO for files
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
with Ada.Unchecked_Deallocation;
with Interfaces.C.Strings;
with Util.Encoders.AES;
with Util.Log.Loggers;
with Util.Systems.Os;
with Util.Systems.Constants;
package body Keystore.IO.Files is

   use type Util.Systems.Types.File_Type;
   use type Interfaces.C.int;
   use Util.Systems.Constants;

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Keystore.IO.Files");

   subtype off_t is Util.Systems.Types.off_t;

   function Sys_Error return String;

   procedure Free is
     new Ada.Unchecked_Deallocation (Object => File_Stream,
                                     Name   => File_Stream_Access);

   function Sys_Error return String is
      Msg : constant Interfaces.C.Strings.chars_ptr
        := Util.Systems.Os.Strerror (Util.Systems.Os.Errno);
   begin
      return Interfaces.C.Strings.Value (Msg);
   end Sys_Error;

   function Hash (Value : Storage_Identifier) return Ada.Containers.Hash_Type is
   begin
      return Ada.Containers.Hash_Type (Value);
   end Hash;

   --  Open the wallet stream.
   procedure Open (Stream : in out Wallet_Stream;
                   Path   : in String) is
   begin
      Stream.Descriptor.Open (Path);
   end Open;

   procedure Create (Stream : in out Wallet_Stream;
                     Path   : in String;
                     Config : in Wallet_Config) is
   begin
      Stream.Descriptor.Create (Path, Config);
   end Create;

   --  Read from the wallet stream the block identified by the number and
   --  call the `Process` procedure with the data block content.
   overriding
   procedure Read (Stream  : in out Wallet_Stream;
                   Block   : in Storage_Block;
                   Process : not null access
                     procedure (Data : in Block_Type)) is
      File : File_Stream_Access;
   begin
      Stream.Descriptor.Get (Block.Storage, File);
      File.Read (Block.Block, Process);
   end Read;

   --  Write in the wallet stream the block identified by the block number.
   overriding
   procedure Write (Stream  : in out Wallet_Stream;
                    Block   : in Storage_Block;
                    Process : not null access
                      procedure (Data : out Block_Type)) is
      File : File_Stream_Access;
   begin
      Stream.Descriptor.Get (Block.Storage, File);
      File.Write (Block.Block, Process);
   end Write;

   --  Allocate a new block and return the block number in `Block`.
   overriding
   procedure Allocate (Stream  : in out Wallet_Stream;
                       Kind    : in Block_Kind;
                       Block   : out Storage_Block) is
      File : File_Stream_Access;
   begin
      Stream.Descriptor.Allocate (Kind, Block.Storage, File);
      File.Allocate (Block.Block);
   end Allocate;

   --  Release the block number.
   overriding
   procedure Release (Stream  : in out Wallet_Stream;
                      Block   : in Storage_Block) is
      File : File_Stream_Access;
   begin
      Stream.Descriptor.Get (Block.Storage, File);
      File.Release (Block.Block);
   end Release;

   overriding
   function Is_Used (Stream  : in out Wallet_Stream;
                     Block   : in Storage_Block) return Boolean is
      File : File_Stream_Access;
   begin
      Stream.Descriptor.Get (Block.Storage, File);
      return File.Is_Used (Block.Block);
   end Is_Used;

   --  Close the wallet stream and release any resource.
   procedure Close (Stream : in out Wallet_Stream) is
   begin
      Stream.Descriptor.Close;
   end Close;

   function Get_Block_Offset (Block : in Block_Number) return off_t is
      (Util.Systems.Types.off_t (Block) * Block_Size - Block_Size);

   protected body File_Stream is

      procedure Open (File_Descriptor : in Util.Systems.Types.File_Type;
                      File_Size       : in Block_Count) is
      begin
         File.Initialize (File_Descriptor);
         Current_Pos := 0;
         Size := File_Size;
      end Open;

      --  Read from the wallet stream the block identified by the number and
      --  call the `Process` procedure with the data block content.
      procedure Read (Block   : in Block_Number;
                      Process : not null access
                        procedure (Data : in Block_Type)) is
         Pos  : constant off_t := Get_Block_Offset (Block);
         Last : Ada.Streams.Stream_Element_Offset;
      begin
         if Pos /= Current_Pos then
            File.Seek (Pos  => Pos, Mode => Util.Systems.Types.SEEK_SET);
         end if;
         File.Read (Data, Last);
         Process (Data);
         Current_Pos := Pos + Block_Size;
      end Read;

      --  Write in the wallet stream the block identified by the block number.
      procedure Write (Block   : in Block_Number;
                       Process : not null access
                         procedure (Data : out Block_Type)) is
         Pos  : constant off_t := Get_Block_Offset (Block);
      begin
         if Pos /= Current_Pos then
            File.Seek (Pos  => Pos, Mode => Util.Systems.Types.SEEK_SET);
         end if;
         Process (Data);
         File.Write (Data);
         Current_Pos := Pos + Block_Size;
      end Write;

      --  ------------------------------
      --  Returns true if the block number is allocated.
      --  ------------------------------
      function Is_Used (Block  : in Block_Number) return Boolean is
      begin
         return Block <= Size and not Free_Blocks.Contains (Block);
      end Is_Used;

      --  ------------------------------
      --  Allocate a new block and return the block number in `Block`.
      --  ------------------------------
      procedure Allocate (Block  : out Block_Number) is
      begin
         if not Free_Blocks.Is_Empty then
            Block := Free_Blocks.First_Element;
            Free_Blocks.Delete_First;
         else
            Size := Size + 1;
            Block := Block_Number (Size);
         end if;
      end Allocate;

      --  ------------------------------
      --  Release the block number.
      --  ------------------------------
      procedure Release (Block  : in Block_Number) is
      begin
         Free_Blocks.Insert (Block);
      end Release;

      procedure Close is
         Last       : Block_Number := Size + 1;
         Free_Block : Block_Number;
         Iter       : Block_Number_Sets.Cursor := Free_Blocks.Last;
      begin
         --  Look at free blocks to see if we can truncate the file when
         --  the last blocks are all deleted.
         while Block_Number_Sets.Has_Element (Iter) loop
            Free_Block := Block_Number_Sets.Element (Iter);
            exit when Free_Block /= Last - 1;
            Last := Last - 1;
            Block_Number_Sets.Previous (Iter);
         end loop;

         --  We have the last deleted block and we can truncate the file to it inclusive.
         if Last /= Size then
            declare
               Length : constant off_t := Get_Block_Offset (Last);
               Result : Integer;
            begin
               Result := Util.Systems.Os.Sys_Ftruncate (File.Get_File, Length);
               if Result /= 0 then
                  Log.Warn ("Truncate to drop deleted blocks failed: {0}", Sys_Error);
               end if;
            end;
         end if;
         File.Close;
      end Close;

   end File_Stream;


   protected body Stream_Descriptor is

      procedure Open (Path : in String) is
         Storage_Id : constant Storage_Identifier := DEFAULT_STORAGE_ID;
         Fd         : Util.Systems.Types.File_Type := Util.Systems.Os.NO_FILE;
         P          : Interfaces.C.Strings.chars_ptr;
         File       : File_Stream_Access;
         Flags      : Interfaces.C.int;
         Stat       : aliased Util.Systems.Types.Stat_Type;
         Size       : Block_Count;
         Result     : Integer;
      begin
         Flags := O_CLOEXEC + O_RDWR;
         P := Interfaces.C.Strings.New_String (Path);
         Fd := Util.Systems.Os.Sys_Open (P, Flags, 8#600#);
         Interfaces.C.Strings.Free (P);

         if Fd = Util.Systems.Os.NO_FILE then
            Log.Error ("Cannot open keystore '{0}': {1}", Path, Sys_Error);
            raise Ada.IO_Exceptions.Name_Error with Path;
         end if;

         Result := Util.Systems.Os.Sys_Fstat (Fd, Stat'Access);
         if Result /= 0 then
            Result := Util.Systems.Os.Sys_Close (Fd);
            Log.Error ("Invalid keystore file '{0}': {1}", Path, Sys_Error);
            raise Ada.IO_Exceptions.Name_Error with Path;
         end if;

         if Stat.st_size mod IO.Block_Size /= 0 then
            Result := Util.Systems.Os.Sys_Close (Fd);
            Log.Error ("Invalid or truncated keystore file '{0}': size is incorrect", Path);
            raise Ada.IO_Exceptions.Name_Error with Path;
         end if;
         Size := Block_Count (Stat.st_size / IO.Block_Size);

         begin
            File := new File_Stream;
            File.Open (Fd, Size);
            Files.Insert (Storage_Id, File);

         exception
            when others =>
               if Fd /= Util.Systems.Os.NO_FILE then
                  Result := Util.Systems.Os.Sys_Close (Fd);
               end if;
               raise;
         end;
      end Open;

      procedure Create (Path   : in String;
                        Config : in Wallet_Config) is
         Storage_Id : constant Storage_Identifier := DEFAULT_STORAGE_ID;
         Fd         : Util.Systems.Types.File_Type := Util.Systems.Os.NO_FILE;
         P          : Interfaces.C.Strings.chars_ptr;
         File       : File_Stream_Access;
         Flags      : Interfaces.C.int;
         Result     : Integer with Unreferenced => True;
      begin
         Flags := O_CREAT + O_TRUNC + O_CLOEXEC + O_RDWR;
         if not Config.Overwrite then
            Flags := Flags + O_EXCL;
         end if;
         P := Interfaces.C.Strings.New_String (Path);
         Fd := Util.Systems.Os.Sys_Open (P, Flags, 8#600#);
         Interfaces.C.Strings.Free (P);
         if Fd = Util.Systems.Os.NO_FILE then
            Log.Error ("Cannot create keystore '{0}': {1}", Path, Sys_Error);
            raise Ada.IO_Exceptions.Name_Error with Path;
         end if;

         File := new File_Stream;
         File.Open (Fd, 0);
         Files.Insert (Storage_Id, File);

      exception
         when others =>
            if Fd /= Util.Systems.Os.NO_FILE then
               Result := Util.Systems.Os.Sys_Close (Fd);
            end if;
            raise;

      end Create;

      procedure Get (Storage : in Storage_Identifier;
                     File    : out File_Stream_Access) is
         Pos : constant File_Stream_Maps.Cursor := Files.Find (Storage);
      begin
         if not File_Stream_Maps.Has_Element (Pos) then
            Log.Error ("Storage{0} not found", Storage_Identifier'Image (Storage));
            raise Keystore.Invalid_Storage;
         end if;
         File := File_Stream_Maps.Element (Pos);
      end Get;

      procedure Allocate (Kind    : in Block_Kind;
                          Storage : out Storage_Identifier;
                          File    : out File_Stream_Access) is
      begin
         if Kind = IO.MASTER_BLOCK or Kind = IO.DIRECTORY_BLOCK then
            Storage := DEFAULT_STORAGE_ID;
         else
            Storage := DEFAULT_STORAGE_ID;
         end if;
         Get (Storage, File);
      end Allocate;

      procedure Close is
         First : File_Stream_Maps.Cursor;
         File  : File_Stream_Access;
      begin
         while not File_Stream_Maps.Is_Empty (Files) loop
            First := Files.First;
            File := File_Stream_Maps.Element (First);
            Files.Delete (First);
            File.Close;
            Free (File);
         end loop;
      end Close;

   end Stream_Descriptor;

end Keystore.IO.Files;
