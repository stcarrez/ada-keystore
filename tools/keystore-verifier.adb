-----------------------------------------------------------------------
--  keystore-verifier -- Toolbox to explore raw content of keystore
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
with Interfaces.C.Strings;
with Ada.IO_Exceptions;
with Ada.Text_IO;
with Util.Systems.Os;
with Util.Systems.Types;
with Util.Systems.Constants;
with Util.Streams.Raw;
with Util.Log.Loggers;
with Util.Encoders;
with Keystore.Buffers;
with Keystore.IO.Headers;
package body Keystore.Verifier is

   use type Interfaces.C.int;
   use type Ada.Text_IO.Count;
   use Ada.Streams;
   use Util.Systems.Constants;
   use Util.Systems.Types;

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Keystore.Verifier");

   function Sys_Error return String is
      Msg : constant Interfaces.C.Strings.chars_ptr
        := Util.Systems.Os.Strerror (Util.Systems.Os.Errno);
   begin
      return Interfaces.C.Strings.Value (Msg);
   end Sys_Error;

   procedure Open (Path   : in String;
                   File   : in out Util.Streams.Raw.Raw_Stream;
                   Sign   : in Secret_Key;
                   Header : in out Keystore.IO.Headers.Wallet_Header) is
      Storage_Id : constant IO.Storage_Identifier := IO.DEFAULT_STORAGE_ID;
      Fd         : Util.Systems.Types.File_Type := Util.Systems.Os.NO_FILE;
      P          : Interfaces.C.Strings.chars_ptr;
      Flags      : Interfaces.C.int;
      Stat       : aliased Util.Systems.Types.Stat_Type;
      Size       : IO.Block_Count;
      Result     : Integer;

      procedure Process (Storage : in IO.Headers.Wallet_Storage) is
      begin
         null;
      end Process;
   begin
      Flags := O_CLOEXEC + O_RDONLY;
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

      Ada.Text_IO.Put ("Path");
      Ada.Text_IO.Set_Col (30);
      Ada.Text_IO.Put_Line (Path);

      Ada.Text_IO.Put ("File size");
      Ada.Text_IO.Set_Col (30 - 1);
      Ada.Text_IO.Put_Line (off_t'Image (Stat.st_size));

      if Stat.st_size mod IO.Block_Size /= 0 then
         Result := Util.Systems.Os.Sys_Close (Fd);
         Log.Error ("Invalid or truncated keystore file '{0}': size is incorrect", Path);
         raise Ada.IO_Exceptions.Name_Error with Path;
      end if;
      Size := IO.Block_Count (Stat.st_size / IO.Block_Size);

      File.Initialize (Fd);
      Header.Buffer := Buffers.Allocate ((Storage_Id, IO.HEADER_BLOCK_NUM));
      declare
         Buf  : constant Buffers.Buffer_Accessor := Header.Buffer.Data.Value;
         Last : Ada.Streams.Stream_Element_Offset;
      begin
         File.Read (Buf.Data, Last);
         Keystore.IO.Headers.Read_Header (Header, Sign, Process'Access);
      end;
   end Open;

   procedure Print_Information (Path : in String) is
      Header : Keystore.IO.Headers.Wallet_Header;
      File   : Util.Streams.Raw.Raw_Stream;
      Sign   : Secret_Key (Length => 32);
      Data   : Ada.Streams.Stream_Element_Array (1 .. 1024);
      Last   : Ada.Streams.Stream_Element_Offset;
      Kind   : Header_Slot_Type;
      Encode : constant Util.Encoders.Encoder := Util.Encoders.Create ("hex");
   begin
      Open (Path   => Path,
            File   => File,
            Sign   => Sign,
            Header => Header);

      Ada.Text_IO.Put ("UUID");
      Ada.Text_IO.Set_Col (30);
      Ada.Text_IO.Put_Line (To_String (Header.UUID));

      Ada.Text_IO.Put ("HMAC");
      Ada.Text_IO.Set_Col (30);
      Ada.Text_IO.Put_Line (Encode.Encode_Binary (Header.HMAC));

      Ada.Text_IO.Put ("Header data");
      Ada.Text_IO.Set_Col (29);
      Ada.Text_IO.Put_Line (Header_Slot_Count_Type'Image (Header.Data_Count));

      for I in 1 .. Header.Data_Count loop
         IO.Headers.Get_Header_Data (Header, I, Kind, Data, Last);
         Ada.Text_IO.Put (Header_Slot_Count_Type'Image (I));
         Ada.Text_IO.Put (" Kind");
         Ada.Text_IO.Set_Col (29);
         Ada.Text_IO.Put (Header_Slot_Type'Image (Kind));
         Ada.Text_IO.Set_Col (39);
         Ada.Text_IO.Put (Stream_Element_Offset'Image (Last));
         Ada.Text_IO.Put (" bytes");
      end loop;
   end Print_Information;

end Keystore.Verifier;
