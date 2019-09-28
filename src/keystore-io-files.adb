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
with Ada.Directories;
with Interfaces.C.Strings;
with Util.Encoders.AES;
with Util.Log.Loggers;
with Util.Systems.Os;
with Util.Systems.Constants;

--  File header
--  +------------------+
--  | 41 64 61 00      | 4b = Ada
--  | 00 9A 72 57      | 4b = 10/12/1815
--  | 01 9D B1 AC      | 4b = 27/11/1852
--  | 00 00 00 01      | 4b = Version 1
--  +------------------+
--  | Keystore UUID    | 16b
--  | Storage ID       | 4b
--  | Block size       | 4b
--  | PAD 0            | 4b
--  | Header HMAC-256  | 32b
--  +------------------+-----
package body Keystore.IO.Files is

   use Ada.Strings.Unbounded;
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

   --  ------------------------------
   --  Open the wallet stream.
   --  ------------------------------
   procedure Open (Stream    : in out Wallet_Stream;
                   Path      : in String;
                   Data_Path : in String) is
   begin
      Stream.Descriptor.Open (Path, Data_Path, Stream.Sign);
   end Open;

   procedure Create (Stream    : in out Wallet_Stream;
                     Path      : in String;
                     Data_Path : in String;
                     Config    : in Wallet_Config) is
   begin
      Stream.Descriptor.Create (Path, Data_Path, Config, Stream.Sign);
      if Config.Storage_Count > 1 then
         Stream.Add_Storage (Config.Storage_Count - 1);
      end if;
   end Create;

   --  ------------------------------
   --  Get information about the keystore file.
   --  ------------------------------
   function Get_Info (Stream : in out Wallet_Stream) return Wallet_Info is
      File   : File_Stream_Access;
   begin
      Stream.Descriptor.Get (DEFAULT_STORAGE_ID, File);
      return File.Get_Info;
   end Get_Info;

   --  ------------------------------
   --  Read from the wallet stream the block identified by the number and
   --  call the `Process` procedure with the data block content.
   --  ------------------------------
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

   --  ------------------------------
   --  Write in the wallet stream the block identified by the block number.
   --  ------------------------------
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

   --  ------------------------------
   --  Allocate a new block and return the block number in `Block`.
   --  ------------------------------
   overriding
   procedure Allocate (Stream  : in out Wallet_Stream;
                       Kind    : in Block_Kind;
                       Block   : out Storage_Block) is
      File : File_Stream_Access;
   begin
      Stream.Descriptor.Allocate (Kind, Block.Storage, File);
      File.Allocate (Block.Block);
   end Allocate;

   --  ------------------------------
   --  Release the block number.
   --  ------------------------------
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

   overriding
   procedure Set_Header_Data (Stream : in out Wallet_Stream;
                              Index  : in Header_Slot_Index_Type;
                              Kind   : in Header_Slot_Type;
                              Data   : in Ada.Streams.Stream_Element_Array) is
      File : File_Stream_Access;
   begin
      Stream.Descriptor.Get (DEFAULT_STORAGE_ID, File);
      File.Set_Header_Data (Index, Kind, Data, Stream.Sign);
   end Set_Header_Data;

   overriding
   procedure Get_Header_Data (Stream : in out Wallet_Stream;
                              Index  : in Header_Slot_Index_Type;
                              Kind   : out Header_Slot_Type;
                              Data   : out Ada.Streams.Stream_Element_Array;
                              Last   : out Ada.Streams.Stream_Element_Offset) is
      File : File_Stream_Access;
   begin
      Stream.Descriptor.Get (DEFAULT_STORAGE_ID, File);
      File.Get_Header_Data (Index, Kind, Data, Last);
   end Get_Header_Data;

   --  ------------------------------
   --  Add up to Count data storage files associated with the wallet.
   --  ------------------------------
   procedure Add_Storage (Stream  : in out Wallet_Stream;
                          Count   : in Positive) is
   begin
      Stream.Descriptor.Add_Storage (Count, Stream.Sign);
   end Add_Storage;

   --  ------------------------------
   --  Close the wallet stream and release any resource.
   --  ------------------------------
   procedure Close (Stream : in out Wallet_Stream) is
   begin
      Stream.Descriptor.Close;
   end Close;

   function Get_Block_Offset (Block : in Block_Number) return off_t is
      (Util.Systems.Types.off_t (Block) * Block_Size);

   protected body File_Stream is

      procedure Open (File_Descriptor : in Util.Systems.Types.File_Type;
                      Storage         : in Storage_Identifier;
                      Sign            : in Secret_Key;
                      File_Size       : in Block_Count;
                      UUID            : out UUID_Type) is
      begin
         File.Initialize (File_Descriptor);
         Size := File_Size;
         Current_Pos := Block_Size;
         Header.Buffer := Buffers.Allocate ((Storage, HEADER_BLOCK_NUM));
         declare
            Buf  : constant Buffers.Buffer_Accessor := Header.Buffer.Data.Value;
            Last : Ada.Streams.Stream_Element_Offset;
         begin
            File.Read (Buf.Data, Last);
            Keystore.IO.Headers.Read_Header (Header, Sign);
            UUID := Header.UUID;
         end;
      end Open;

      procedure Create (File_Descriptor : in Util.Systems.Types.File_Type;
                        Storage         : in Storage_Identifier;
                        UUID            : in UUID_Type;
                        Sign            : in Secret_Key) is
      begin
         File.Initialize (File_Descriptor);
         Size := 1;
         Current_Pos := Block_Size;
         Header.Buffer := Buffers.Allocate ((Storage, HEADER_BLOCK_NUM));
         Header.UUID := UUID;
         Keystore.IO.Headers.Build_Header (UUID, Storage, Header);
         Keystore.IO.Headers.Sign_Header (Header, Sign);
         declare
            Buf  : constant Buffers.Buffer_Accessor := Header.Buffer.Data.Value;
         begin
            File.Write (Buf.Data);
         end;
      end Create;

      function Get_Info return Wallet_Info is
         Result : Wallet_Info;
      begin
         Result.UUID := Header.UUID;
         Result.Header_Count  := Header.Data_Count;
         Result.Storage_Count := Header.Storage_Count;
         return Result;
      end Get_Info;

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
            Block := Block_Number (Size);
            Size := Size + 1;
         end if;
      end Allocate;

      --  ------------------------------
      --  Release the block number.
      --  ------------------------------
      procedure Release (Block  : in Block_Number) is
      begin
         Free_Blocks.Insert (Block);
      end Release;

      procedure Save_Header (Sign : in Secret_Key) is
         Buf  : constant Buffers.Buffer_Accessor := Header.Buffer.Data.Value;
      begin
         Keystore.IO.Headers.Sign_Header (Header, Sign);
         File.Seek (Pos  => 0, Mode => Util.Systems.Types.SEEK_SET);
         File.Write (Buf.Data);
         Current_Pos := Block_Size;
      end Save_Header;

      procedure Set_Header_Data (Index  : in Header_Slot_Index_Type;
                                 Kind   : in Header_Slot_Type;
                                 Data   : in Ada.Streams.Stream_Element_Array;
                                 Sign   : in Secret_Key) is
      begin
         IO.Headers.Set_Header_Data (Header, Index, Kind, Data);
         Save_Header (Sign);
      end Set_Header_Data;

      procedure Get_Header_Data (Index  : in Header_Slot_Index_Type;
                                 Kind   : out Header_Slot_Type;
                                 Data   : out Ada.Streams.Stream_Element_Array;
                                 Last   : out Ada.Streams.Stream_Element_Offset) is
      begin
         IO.Headers.Get_Header_Data (Header, Index, Kind, Data, Last);
      end Get_Header_Data;

      procedure Add_Storage (Identifier : in Storage_Identifier;
                             Sign       : in Secret_Key) is
         Pos : Block_Index;
      begin
         IO.Headers.Add_Storage (Header, Identifier, 1, Pos);
         Save_Header (Sign);
      end Add_Storage;

      procedure Scan_Storage (Process : not null
                              access procedure (Storage : in Wallet_Storage)) is
      begin
         IO.Headers.Scan_Storage (Header, Process);
      end Scan_Storage;

      procedure Close is
         Last       : Block_Number := Size;
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

      function Get_Storage_Path (Storage_Id : in Storage_Identifier) return String is
         Prefix : constant String := To_String (UUID);
         Index  : constant String := Storage_Identifier'Image (Storage_Id);
         Name   : constant String := Prefix & "-" & Index (Index'First + 1 .. Index'Last);
      begin
         return Ada.Directories.Compose (To_String (Directory), Name & ".dkt");
      end Get_Storage_Path;

      procedure Open (Path       : in String;
                      Identifier : in Storage_Identifier;
                      Sign       : in Secret_Key;
                      Tag        : out UUID_Type) is
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

         File := new File_Stream;
         Files.Insert (Identifier, File);
         File.Open (Fd, Identifier, Sign, Size, Tag);
      end Open;

      procedure Open (Path      : in String;
                      Data_Path : in String;
                      Sign      : in Secret_Key) is

         procedure Open_Storage (Storage : in Wallet_Storage) is
            Path : constant String := Get_Storage_Path (Storage.Identifier);
            Tag  : UUID_Type;
         begin
            Open (Path, Storage.Identifier, Sign, Tag);
            if Tag /= UUID then
               Log.Error ("Invalid UUID for storage file {0}", Path);
            end if;
            if Storage.Identifier > Last_Id then
               Last_Id := Storage.Identifier;
            end if;
            Alloc_Id := 1;
         end Open_Storage;

         File : File_Stream_Access;
      begin
         Directory := To_Unbounded_String (Data_Path);
         Open (Path, DEFAULT_STORAGE_ID, Sign, UUID);
         Get (DEFAULT_STORAGE_ID, File);
         Last_Id := DEFAULT_STORAGE_ID;
         File.Scan_Storage (Open_Storage'Access);
      end Open;

      procedure Create (Path      : in String;
                        Data_Path : in String;
                        Config    : in Wallet_Config;
                        Sign      : in Secret_Key) is
         Fd         : Util.Systems.Types.File_Type := Util.Systems.Os.NO_FILE;
         P          : Interfaces.C.Strings.chars_ptr;
         File       : File_Stream_Access;
         Flags      : Interfaces.C.int;
         Result     : Integer with Unreferenced => True;
      begin
         Directory := To_Unbounded_String (Data_Path);
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
         Random.Generate (UUID);
         File.Create (Fd, DEFAULT_STORAGE_ID, UUID, Sign);
         Files.Insert (DEFAULT_STORAGE_ID, File);
         Last_Id := DEFAULT_STORAGE_ID;
      end Create;

      procedure Create_Storage (Storage_Id : in Storage_Identifier;
                                Sign       : in Secret_Key) is
         Path    : constant String := Get_Storage_Path (Storage_Id);
         Fd      : Util.Systems.Types.File_Type := Util.Systems.Os.NO_FILE;
         P       : Interfaces.C.Strings.chars_ptr;
         File    : File_Stream_Access;
         Flags   : Interfaces.C.int;
         Result  : Integer with Unreferenced => True;
      begin
         Flags := O_CREAT + O_TRUNC + O_CLOEXEC + O_RDWR;
         P := Interfaces.C.Strings.New_String (Path);
         Fd := Util.Systems.Os.Sys_Open (P, Flags, 8#600#);
         Interfaces.C.Strings.Free (P);
         if Fd = Util.Systems.Os.NO_FILE then
            Log.Error ("Cannot create keystore storage '{0}': {1}", Path, Sys_Error);
            raise Ada.IO_Exceptions.Name_Error with Path;
         end if;

         File := new File_Stream;
         File.Create (Fd, Storage_Id, UUID, Sign);
         Files.Insert (Storage_Id, File);
      end Create_Storage;

      procedure Add_Storage (Count : in Positive;
                             Sign  : in Secret_Key) is
         File : File_Stream_Access;
      begin
         Get (DEFAULT_STORAGE_ID, File);
         for I in 1 .. Count loop
            Last_Id := Last_Id + 1;
            Create_Storage (Last_Id, Sign);
            File.Add_Storage (Last_Id, Sign);
         end loop;
         if Alloc_Id = DEFAULT_STORAGE_ID then
            Alloc_Id := 1;
         end if;
      end Add_Storage;

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
         if Kind = IO.MASTER_BLOCK or Kind = IO.DIRECTORY_BLOCK or Last_Id <= DEFAULT_STORAGE_ID then
            Storage := DEFAULT_STORAGE_ID;
         else
            Storage := Alloc_Id;
            Alloc_Id := Alloc_Id + 1;
            if Alloc_Id > Last_Id then
               Alloc_Id := 1;
            end if;
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
