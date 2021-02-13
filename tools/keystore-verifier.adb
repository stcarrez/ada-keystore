-----------------------------------------------------------------------
--  keystore-verifier -- Toolbox to explore raw content of keystore
--  Copyright (C) 2019, 2021 Stephane Carrez
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
with Util.Strings;
with Util.Systems.Os;
with Util.Systems.Types;
with Util.Systems.Constants;
with Util.Streams.Raw;
with Util.Log.Loggers;
with Util.Encoders;
with Keystore.Buffers;
with Keystore.Marshallers;
with Keystore.IO.Headers;
with Keystore.Passwords.GPG;
with Intl;
package body Keystore.Verifier is

   use type Interfaces.Unsigned_16;
   use type Interfaces.Unsigned_32;
   use type Interfaces.C.int;
   use type Ada.Text_IO.Count;
   use Ada.Streams;
   use Util.Systems.Constants;
   use Util.Systems.Types;
   use type Keystore.Buffers.Block_Count;
   use type Keystore.IO.Storage_Identifier;

   function "-" (Message : in String) return String is (Intl."-" (Message));
   function Sys_Error return String;
   function Get_Storage_Id (Path : in String) return IO.Storage_Identifier;

   procedure Open (Path   : in String;
                   File   : in out Util.Streams.Raw.Raw_Stream;
                   Sign   : in Secret_Key;
                   Header : in out Keystore.IO.Headers.Wallet_Header;
                   Is_Keystore : out Boolean);

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Keystore.Verifier");

   function Sys_Error return String is
      Msg : constant Interfaces.C.Strings.chars_ptr
        := Util.Systems.Os.Strerror (Util.Systems.Os.Errno);
   begin
      return Interfaces.C.Strings.Value (Msg);
   end Sys_Error;

   function Get_Storage_Id (Path : in String) return IO.Storage_Identifier is
      Pos : Natural;
   begin
      if Util.Strings.Ends_With (Path, ".dkt") then
         Pos := Util.Strings.Rindex (Path, '-');
         if Pos = 0 then
            return IO.DEFAULT_STORAGE_ID;
         end if;
         return IO.Storage_Identifier'Value (Path (Pos + 1 .. Path'Last - 4));
      else
         return IO.DEFAULT_STORAGE_ID;
      end if;

   exception
      when Constraint_Error =>
         return IO.DEFAULT_STORAGE_ID;
   end Get_Storage_Id;

   procedure Open (Path   : in String;
                   File   : in out Util.Streams.Raw.Raw_Stream;
                   Sign   : in Secret_Key;
                   Header : in out Keystore.IO.Headers.Wallet_Header;
                   Is_Keystore : out Boolean) is

      --  Compilation on Windows requires this type visibility but GNAT 2019 complains.
      pragma Warnings (Off);
      use type Util.Systems.Types.File_Type;
      pragma Warnings (On);

      Storage_Id : constant IO.Storage_Identifier := Get_Storage_Id (Path);
      Fd         : Util.Systems.Types.File_Type := Util.Systems.Os.NO_FILE;
      P          : Interfaces.C.Strings.chars_ptr;
      Flags      : Interfaces.C.int;
      Stat       : aliased Util.Systems.Types.Stat_Type;
      Result     : Integer;
   begin
      Flags := O_CLOEXEC + O_RDONLY;
      P := Interfaces.C.Strings.New_String (Path);
      Fd := Util.Systems.Os.Sys_Open (P, Flags, 8#600#);
      Interfaces.C.Strings.Free (P);

      if Fd = Util.Systems.Os.NO_FILE then
         Log.Error (-("cannot open keystore '{0}': {1}"), Path, Sys_Error);
         raise Ada.IO_Exceptions.Name_Error with Path;
      end if;

      Result := Util.Systems.Os.Sys_Fstat (Fd, Stat'Access);
      if Result /= 0 then
         Result := Util.Systems.Os.Sys_Close (Fd);
         Log.Error (-("invalid keystore file '{0}': {1}"), Path, Sys_Error);
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
         Log.Error (-("invalid or truncated keystore file '{0}': size is incorrect"), Path);
         raise Ada.IO_Exceptions.Name_Error with Path;
      end if;

      File.Initialize (Fd);
      Header.Buffer := Buffers.Allocate ((Storage_Id, IO.HEADER_BLOCK_NUM));
      declare
         Buf  : constant Buffers.Buffer_Accessor := Header.Buffer.Data.Value;
         Last : Ada.Streams.Stream_Element_Offset;
         Data : Keystore.IO.IO_Block_Type;
      begin
         File.Read (Data, Last);
         if Last /= Data'Last then
            Log.Warn ("Header block is too short");
            raise Invalid_Keystore;
         end if;
         Buf.Data := Data (Buf.Data'Range);
         Keystore.IO.Headers.Sign_Header (Header, Sign);
         if Header.HMAC /= Data (Keystore.IO.BT_HMAC_HEADER_POS .. Data'Last) then
            Log.Warn ("Header block HMAC signature is invalid");
            --  raise Invalid_Block;
         end if;
         Keystore.IO.Headers.Read_Header (Header);

         Is_Keystore := Storage_Id = IO.DEFAULT_STORAGE_ID;
         Ada.Text_IO.Put ("Type");
         Ada.Text_IO.Set_Col (30);
         if not Is_Keystore then
            Ada.Text_IO.Put ("storage");
            Ada.Text_IO.Put_Line (IO.Storage_Identifier'Image (Storage_Id));
         else
            Ada.Text_IO.Put_Line ("keystore");
         end if;
      end;
   end Open;

   procedure Print_Information (Path        : in String;
                                Is_Keystore : out Boolean) is
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
            Header => Header,
            Is_Keystore => Is_Keystore);

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
         Ada.Text_IO.Put (" bytes ");
         Ada.Text_IO.Put_Line (Keystore.Passwords.GPG.Extract_Key_Id (Data));
      end loop;

      declare
         procedure Report;

         Buf    : constant Buffers.Buffer_Accessor := Header.Buffer.Data.Value;
         Last   : Ada.Streams.Stream_Element_Offset;
         Data   : Keystore.IO.IO_Block_Type;
         Block  : IO.Block_Number := 1;
         Buffer : Keystore.Marshallers.Marshaller;
         Btype  : Interfaces.Unsigned_16;
         Esize  : Interfaces.Unsigned_16 with Unreferenced;
         Id     : Interfaces.Unsigned_32;
         Current_Id   : Interfaces.Unsigned_32 := 0;
         Current_Type : Interfaces.Unsigned_16 := 0;
         First_Block  : IO.Block_Number := 1;

         procedure Report is
         begin
            Ada.Text_IO.Put (IO.Block_Number'Image (First_Block));
            if First_Block + 1 < Block then
               Ada.Text_IO.Put ("..");
               Ada.Text_IO.Put (IO.Block_Number'Image (Block - 1));
            end if;
            Ada.Text_IO.Put (" Wallet");
            Ada.Text_IO.Put (Interfaces.Unsigned_32'Image (Current_Id));
            if Current_Type = IO.BT_WALLET_DIRECTORY then
               Ada.Text_IO.Put (" Directory");
            elsif Current_Type = IO.BT_WALLET_HEADER then
               Ada.Text_IO.Put (" Header");
            elsif Current_Type = IO.BT_WALLET_DATA then
               Ada.Text_IO.Put (" Data");
            else
               Ada.Text_IO.Put (" Unkown");
            end if;
            Ada.Text_IO.New_Line;
         end Report;

      begin
         loop
            File.Read (Data, Last);
            exit when Last /= Data'Last;
            Buffer.Buffer := Header.Buffer;
            Buf.Data := Data (Buf.Data'Range);
            Btype := Marshallers.Get_Header_16 (Buffer);
            Esize := Marshallers.Get_Unsigned_16 (Buffer);
            Id := Marshallers.Get_Unsigned_32 (Buffer);
            if Btype /= Current_Type or Id /= Current_Id then
               if Current_Id > 0 then
                  Report;
               end if;
               Current_Id := Id;
               Current_Type := Btype;
               First_Block := Block;
            end if;
            Block := Block + 1;
         end loop;
         Report;
      end;
   end Print_Information;

end Keystore.Verifier;
