-----------------------------------------------------------------------
--  keystore-passwords-files -- File based password provider
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
with Ada.Directories;
with Ada.Streams.Stream_IO;
with Util.Systems.Types;
with Util.Systems.Os;
with Keystore.Random;
package body Keystore.Passwords.Files is

   subtype Key_Length is Util.Encoders.Key_Length;

   use type Ada.Streams.Stream_Element_Offset;

   --  GNAT 2019 complains about unused use type but gcc 7.4 fails if it not defined (st_mode).
   pragma Warnings (Off);
   use type Interfaces.C.unsigned;
   use type Interfaces.C.unsigned_short;
   pragma Warnings (On);

   function Verify_And_Get_Size (Path : in String) return Ada.Streams.Stream_Element_Count;

   type Provider (Len : Key_Length) is limited new Keystore.Passwords.Provider with record
      Password : Ada.Streams.Stream_Element_Array (1 .. Len);
   end record;
   type File_Provider_Access is access all Provider;

   --  Get the password through the Getter operation.
   overriding
   procedure Get_Password (From   : in Provider;
                           Getter : not null access procedure (Password : in Secret_Key));

   type Key_Provider (Len : Key_Length) is new Provider (Len)
     and Keys.Key_Provider with null record;
   type Key_Provider_Access is access all Key_Provider'Class;

   --  Get the Key, IV and signature.
   procedure Get_Keys (From : in Key_Provider;
                       Key  : out Secret_Key;
                       IV   : out Secret_Key;
                       Sign : out Secret_Key);

   function Verify_And_Get_Size (Path : in String) return Ada.Streams.Stream_Element_Count is
      P       : Interfaces.C.Strings.chars_ptr;
      Stat    : aliased Util.Systems.Types.Stat_Type;
      Res     : Integer;
      Result  : Ada.Streams.Stream_Element_Count;
   begin
      --  Verify that the file is readable only by the current user.
      P := Interfaces.C.Strings.New_String (Path);
      Res := Util.Systems.Os.Sys_Stat (Path => P,
                                       Stat => Stat'Access);
      Interfaces.C.Strings.Free (P);
      if Res /= 0 then
         raise Keystore.Bad_Password with "Password file does not exist";
      end if;
      if (Stat.st_mode and 8#0077#) /= 0 then
         raise Keystore.Bad_Password with "Password file is not safe";
      end if;
      if Stat.st_size = 0 then
         raise Keystore.Bad_Password with "Password file is empty";
      end if;
      if Stat.st_size > MAX_FILE_SIZE then
         raise Keystore.Bad_Password with "Password file is too big";
      end if;
      Result := Ada.Streams.Stream_Element_Offset (Stat.st_size);

      --  Verify that the parent directory is readable only by the current user.
      P := Interfaces.C.Strings.New_String (Ada.Directories.Containing_Directory (Path));
      Res := Util.Systems.Os.Sys_Stat (Path => P,
                                       Stat => Stat'Access);
      Interfaces.C.Strings.Free (P);
      if Res /= 0 then
         raise Keystore.Bad_Password
         with "Directory that contains password file cannot be checked";
      end if;
      if (Stat.st_mode and 8#0077#) /= 0 then
         raise Keystore.Bad_Password
         with "Directory that contains password file is not safe";
      end if;

      return Result;
   end Verify_And_Get_Size;

   --  ------------------------------
   --  Create a password provider that reads the file to build the password.
   --  The file must have the mode rw------- (600) and its owning directory
   --  the mode rwx------ (700).  The Bad_Password exception is raised if
   --  these rules are not verified.
   --  ------------------------------
   function Create (Path : in String) return Provider_Access is
      Size    : Ada.Streams.Stream_Element_Offset;
      File    : Ada.Streams.Stream_IO.File_Type;
      Result  : File_Provider_Access;
      Last    : Ada.Streams.Stream_Element_Offset;
   begin
      Size := Verify_And_Get_Size (Path);

      Ada.Streams.Stream_IO.Open (File => File,
                                  Mode => Ada.Streams.Stream_IO.In_File,
                                  Name => Path);

      Result := new Provider '(Len => Size,
                               others => <>);
      Ada.Streams.Stream_IO.Read (File, Result.Password, Last);
      Ada.Streams.Stream_IO.Close (File);
      return Result.all'Access;
   end Create;

   --  ------------------------------
   --  Get the password through the Getter operation.
   --  ------------------------------
   overriding
   procedure Get_Password (From   : in Provider;
                           Getter : not null access procedure (Password : in Secret_Key)) is
      Password : Keystore.Secret_Key (Length => From.Len);
   begin
      Util.Encoders.Create (From.Password, Password);
      Getter (Password);
   end Get_Password;

   --  ------------------------------
   --  Create a key provider that reads the file.  The file is split in three parts
   --  the key, the IV, the signature which are extracted by using `Get_Keys`.
   --  ------------------------------
   function Create (Path : in String) return Keys.Key_Provider_Access is
      Size    : Ada.Streams.Stream_Element_Offset;
      File    : Ada.Streams.Stream_IO.File_Type;
      Result  : Key_Provider_Access;
      Last    : Ada.Streams.Stream_Element_Offset;
   begin
      Size := Verify_And_Get_Size (Path);

      Ada.Streams.Stream_IO.Open (File => File,
                                  Mode => Ada.Streams.Stream_IO.In_File,
                                  Name => Path);

      Result := new Key_Provider '(Len => Size,
                                   others => <>);
      Ada.Streams.Stream_IO.Read (File, Result.Password, Last);
      Ada.Streams.Stream_IO.Close (File);
      return Result.all'Access;
   end Create;

   --  ------------------------------
   --  Get the Key, IV and signature.
   --  ------------------------------
   overriding
   procedure Get_Keys (From : in Key_Provider;
                       Key  : out Secret_Key;
                       IV   : out Secret_Key;
                       Sign : out Secret_Key) is
      First : Ada.Streams.Stream_Element_Offset := 1;
      Last  : Ada.Streams.Stream_Element_Offset := First + Key.Length - 1;
   begin
      if From.Len /= Key.Length + IV.Length + Sign.Length then
         raise Keystore.Bad_Password with "Invalid length for the key file";
      end if;
      Util.Encoders.Create (From.Password (First .. Last), Key);
      First := Last + 1;
      Last := First + IV.Length - 1;
      Util.Encoders.Create (From.Password (First .. Last), IV);
      First := Last + 1;
      Last := First + Sign.Length - 1;
      Util.Encoders.Create (From.Password (First .. Last), Sign);
   end Get_Keys;

   --  ------------------------------
   --  Generate a file that contains the keys.  Keys are generated using a random generator.
   --  The file is created with the mode rw------- (600) and the owning directory is forced
   --  to the mode rwx------ (700).
   --  ------------------------------
   function Generate (Path   : in String;
                      Length : in Key_Length := DEFAULT_KEY_FILE_LENGTH)
                      return Keys.Key_Provider_Access is
      Result  : Key_Provider_Access;
      Random  : Keystore.Random.Generator;
      Dir     : constant String := Ada.Directories.Containing_Directory (Path);
      File    : Ada.Streams.Stream_IO.File_Type;
      P       : Interfaces.C.Strings.chars_ptr;
      Res     : Integer;
   begin
      if not Ada.Directories.Exists (Dir) then
         Ada.Directories.Create_Path (Dir);
      end if;

      Ada.Streams.Stream_IO.Create (File => File,
                                    Mode => Ada.Streams.Stream_IO.Out_File,
                                    Name => Path);

      Result := new Key_Provider '(Len => Length,
                                   others => <>);
      Random.Generate (Result.Password);
      Ada.Streams.Stream_IO.Write (File, Result.Password);
      Ada.Streams.Stream_IO.Close (File);

      P := Interfaces.C.Strings.New_String (Path);
      Res := Util.Systems.Os.Sys_Chmod (Path => P,
                                        Mode => 8#0600#);
      Interfaces.C.Strings.Free (P);

      P := Interfaces.C.Strings.New_String (Dir);
      Res := Util.Systems.Os.Sys_Chmod (Path => P,
                                        Mode => 8#0700#);
      Interfaces.C.Strings.Free (P);

      return Result.all'Access;
   end Generate;

end Keystore.Passwords.Files;
