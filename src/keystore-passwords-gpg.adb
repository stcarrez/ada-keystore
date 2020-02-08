-----------------------------------------------------------------------
--  keystore-passwords-gpg -- Password protected by GPG
--  Copyright (C) 2019, 2020 Stephane Carrez
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
with Ada.Unchecked_Deallocation;
with Ada.Exceptions;
with Ada.Strings.Fixed;
with GNAT.Regpat;
with Util.Streams;
with Util.Log.Loggers;
with Util.Encoders;
with Util.Processes;
with Util.Streams.Texts;
with Keystore.Random;

--  === GPG Header data ===
--
--  The GPG encrypted data contains the following information:
--  ```
--  +------------------+-----
--  | TAG              | 4b
--  +------------------+-----
--  | Lock Key         | 32b
--  | Lock IV          | 16b
--  | Wallet Key       | 32b
--  | Wallet IV        | 16b
--  | Wallet Sign      | 32b
--  +------------------+-----
--  ```
package body Keystore.Passwords.GPG is

   use Ada.Streams;
   use Ada.Strings.Unbounded;

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Keystore.Passwords.GPG");

   function Get_Le_Long (Data : in Ada.Streams.Stream_Element_Array)
                         return Interfaces.Unsigned_32;
   function Get_Unsigned_32 (Data : in Stream_Element_Array) return Interfaces.Unsigned_32;
   procedure Put_Unsigned_32 (Data  : out Stream_Element_Array;
                              Value : in Interfaces.Unsigned_32);

   --  Headers of GPG packet.
   GPG_OLD_TAG_1 : constant Ada.Streams.Stream_Element := 16#85#;
   GPG_NEW_VERSION : constant Ada.Streams.Stream_Element := 16#03#;

   function Get_Unsigned_32 (Data : in Stream_Element_Array) return Interfaces.Unsigned_32 is
      use Interfaces;
   begin
      return Shift_Left (Unsigned_32 (Data (Data'First)), 24) or
        Shift_Left (Unsigned_32 (Data (Data'First + 1)), 16) or
        Shift_Left (Unsigned_32 (Data (Data'First + 2)), 8) or
        Unsigned_32 (Data (Data'First + 3));
   end Get_Unsigned_32;

   procedure Put_Unsigned_32 (Data  : out Stream_Element_Array;
                              Value : in Interfaces.Unsigned_32) is
      use Interfaces;
   begin
      Data (Data'First) := Stream_Element (Shift_Right (Value, 24));
      Data (Data'First + 1) := Stream_Element (Shift_Right (Value, 16) and 16#0ff#);
      Data (Data'First + 2) := Stream_Element (Shift_Right (Value, 8) and 16#0ff#);
      Data (Data'First + 3) := Stream_Element (Value and 16#0ff#);
   end Put_Unsigned_32;

   function Get_Le_Long (Data : in Ada.Streams.Stream_Element_Array)
                         return Interfaces.Unsigned_32 is
      use Interfaces;
   begin
      return Shift_Left (Unsigned_32 (Data (Data'First)), 24) or
        Shift_Left (Unsigned_32 (Data (Data'First + 1)), 16) or
        Shift_Left (Unsigned_32 (Data (Data'First + 2)), 8) or
        Unsigned_32 (Data (Data'First + 3));
   end Get_Le_Long;

   --  ------------------------------
   --  Extract the Key ID from the data content when it is encrypted by GPG2.
   --  ------------------------------
   function Extract_Key_Id (Data : in Ada.Streams.Stream_Element_Array) return String is
      L1 : Interfaces.Unsigned_32;
      L2 : Interfaces.Unsigned_32;
      Encode : constant Util.Encoders.Encoder := Util.Encoders.Create ("hex");
   begin
      if Data'Length < 16 then
         return "";
      end if;
      if Data (Data'First + 4) /= GPG_OLD_TAG_1 then
         return "";
      end if;
      if Data (Data'First + 7) /= GPG_NEW_VERSION then
         return "";
      end if;
      if Data (Data'First + 5) > 4 then
         return "";
      end if;

      L1 := Get_Le_Long (Data (Data'First + 4 + 4 .. Data'Last));
      L2 := Get_Le_Long (Data (Data'First + 8 + 4 .. Data'Last));
      return Encode.Encode_Unsigned_32 (L1) & Encode.Encode_Unsigned_32 (L2);
   end Extract_Key_Id;

   --  ------------------------------
   --  Get the list of GPG secret keys that could be capable for decrypting a content for us.
   --  ------------------------------
   procedure List_GPG_Secret_Keys (Context : in out Context_Type;
                                   List    : in out Util.Strings.Sets.Set) is
      procedure Parse (Line : in String);

      --  GPG1 command output:
      --  ssb::<key-size>:<key-algo>:<key-id>:<create-date>:<expire-date>:::::<e>:
      REGEX1 : constant String
        := "^(ssb|sec):u?:[1-9][0-9][0-9][0-9]:[0-9]:([0-9a-fA-F]+):[0-9-]+:[0-9-]*:::::.*";

      --  GPG2 command output:
      --  ssb:u:<key-size>:<key-algo>:<key-id>:<create-date>:<expire-date>:::::<e>:
      REGEX2 : constant String
        := "^(ssb|sec):u?:[1-9][0-9][0-9][0-9]:[0-9]:([0-9a-fA-F]+):[0-9]+:[0-9]*:::::[esa]+::.*";

      Pattern1 : constant GNAT.Regpat.Pattern_Matcher := GNAT.Regpat.Compile (REGEX1);
      Pattern2 : constant GNAT.Regpat.Pattern_Matcher := GNAT.Regpat.Compile (REGEX2);

      procedure Parse (Line : in String) is
         Matches : GNAT.Regpat.Match_Array (0 .. 2);
      begin
         if GNAT.Regpat.Match (Pattern2, Line) then
            GNAT.Regpat.Match (Pattern2, Line, Matches);
            List.Include (Line (Matches (2).First .. Matches (2).Last));

         elsif GNAT.Regpat.Match (Pattern1, Line) then
            GNAT.Regpat.Match (Pattern1, Line, Matches);
            List.Include (Line (Matches (2).First .. Matches (2).Last));

         end if;
      end Parse;

      Command : constant String := To_String (Context.List_Key_Command);
      Proc    : Util.Processes.Process;
      Output  : Util.Streams.Input_Stream_Access;
      Input   : Util.Streams.Output_Stream_Access;
      Reader  : Util.Streams.Texts.Reader_Stream;
   begin
      Log.Info ("Looking for GPG secrets using {0}", Command);

      Util.Processes.Spawn (Proc    => Proc,
                            Command => Command,
                            Mode    => Util.Processes.READ_WRITE_ALL);
      Input := Util.Processes.Get_Input_Stream (Proc);
      Output := Util.Processes.Get_Output_Stream (Proc);
      Reader.Initialize (Output, 4096);
      Input.Close;

      while not Reader.Is_Eof loop
         declare
            Line : Ada.Strings.Unbounded.Unbounded_String;
         begin
            Reader.Read_Line (Line);
            Parse (To_String (Line));
         end;
      end loop;
      Util.Processes.Wait (Proc);
      if Util.Processes.Get_Exit_Status (Proc) /= 0 then
         Log.Warn ("GPG list command '{0}' terminated with exit code{1}", Command,
                   Natural'Image (Util.Processes.Get_Exit_Status (Proc)));
      end if;

   exception
      when E : Util.Processes.Process_Error =>
         Log.Warn ("Cannot execute GPG command '{0}': {1}",
                   Command, Ada.Exceptions.Exception_Message (E));

   end List_GPG_Secret_Keys;

   --  ------------------------------
   --  Create a secret to protect the keystore.
   --  ------------------------------
   procedure Create_Secret (Context : in out Context_Type;
                            Data    : in Ada.Streams.Stream_Element_Array) is
      P   : Secret_Provider_Access;
      Tag : constant Tag_Type := Get_Unsigned_32 (Data);
   begin
      P := new Secret_Provider '(Tag    => Tag,
                                 Next   => Context.First,
                                 others => <>);
      Context.First := P;
      Util.Encoders.Create (Data (POS_LOCK_KEY .. POS_LOCK_KEY_LAST), P.Key);
      Util.Encoders.Create (Data (POS_LOCK_IV .. POS_LOCK_IV_LAST), P.IV);
      Context.Current := P;
   end Create_Secret;

   --  ------------------------------
   --  Create a secret to protect the keystore.
   --  ------------------------------
   procedure Create_Secret (Context : in out Context_Type) is
      Rand : Keystore.Random.Generator;
   begin
      Rand.Generate (Context.Data);
      Context.Create_Secret (Context.Data);
   end Create_Secret;

   procedure Create_Secret (Context : in out Context_Type;
                            Image   : in Context_Type'Class) is
   begin
      Context.Encrypt_Command := Image.Encrypt_Command;
      Context.Decrypt_Command := Image.Decrypt_Command;
      Context.List_Key_Command := Image.List_Key_Command;
      Context.Create_Secret;
      Context.Data (POS_WALLET_KEY .. POS_WALLET_SIGN_LAST)
        := Image.Data (POS_WALLET_KEY .. POS_WALLET_SIGN_LAST);
   end Create_Secret;

   procedure Create_Secret (Context      : in out Context_Type;
                            Key_Provider : in Keys.Key_Provider'Class) is
   begin
      Context.Create_Secret;
      if Key_Provider in Keystore.Passwords.Internal_Key_Provider'Class then
         Keystore.Passwords.Internal_Key_Provider'Class (Key_Provider).Save_Key
           (Context.Data (POS_WALLET_KEY .. POS_WALLET_SIGN_LAST));
      end if;
   end Create_Secret;

   --  ------------------------------
   --  Save the GPG secret by encrypting it using the user's GPG key and storing
   --  the encrypted data in the keystore data header.
   --  ------------------------------
   procedure Save_Secret (Context : in out Context_Type;
                          User    : in String;
                          Index   : in Keystore.Header_Slot_Index_Type;
                          Wallet  : in out Keystore.Files.Wallet_File) is
      Cmd    : constant String := Context.Get_Encrypt_Command (User);
      Proc   : Util.Processes.Process;
      Result : Ada.Streams.Stream_Element_Array (1 .. MAX_ENCRYPT_SIZE);
      Last   : Ada.Streams.Stream_Element_Offset := 0;
      Last2  : Ada.Streams.Stream_Element_Offset;
      Input  : Util.Streams.Output_Stream_Access;
      Output : Util.Streams.Input_Stream_Access;
   begin
      Log.Info ("Encrypt GPG secret using {0}", Cmd);

      Put_Unsigned_32 (Result, Context.Current.Tag);
      Last := 4;
      Util.Processes.Spawn (Proc    => Proc,
                            Command => Cmd,
                            Mode    => Util.Processes.READ_WRITE);

      Input := Util.Processes.Get_Input_Stream (Proc);
      Input.Write (Context.Data (POS_LOCK_KEY .. Context.Data'Last));
      Input.Close;

      Output := Util.Processes.Get_Output_Stream (Proc);
      while Last < Result'Last loop
         Output.Read (Result (Last + 1 .. Result'Last), Last2);
         exit when Last2 = Last;
         Last := Last2;
      end loop;

      Util.Processes.Wait (Proc);
      if Util.Processes.Get_Exit_Status (Proc) /= 0 or Last <= 4 then
         Log.Warn ("GPG encrypt command '{0}' terminated with exit code{1}", Cmd,
                   Natural'Image (Util.Processes.Get_Exit_Status (Proc)));
         raise Keystore.Bad_Password;
      end if;

      Keystore.Files.Set_Header_Data (Wallet, Index,
                                      Keystore.SLOT_KEY_GPG2, Result (1 .. Last));
      Context.Index := Context.Index + 1;

   exception
      when E : Util.Processes.Process_Error =>
         Log.Warn ("Cannot execute GPG encrypt command '{0}': {1}",
                   Cmd, Ada.Exceptions.Exception_Message (E));
         raise Keystore.Bad_Password;

   end Save_Secret;

   --  ------------------------------
   --  Load the GPG secrets stored in the keystore header.
   --  ------------------------------
   procedure Load_Secrets (Context : in out Context_Type;
                           Wallet  : in out Keystore.Files.Wallet_File) is
      Data : Ada.Streams.Stream_Element_Array (1 .. MAX_ENCRYPT_SIZE);
      Last : Ada.Streams.Stream_Element_Offset;
      Kind : Keystore.Header_Slot_Type;
      List : Util.Strings.Sets.Set;
   begin
      --  Get the list of known secret keys.
      Context.List_GPG_Secret_Keys (List);

      for Index in Header_Slot_Index_Type'Range loop
         Wallet.Get_Header_Data (Index, Kind, Data, Last);
         exit when Last < Data'First;
         if Kind = Keystore.SLOT_KEY_GPG2 then
            declare
               Key_Id : constant String := Extract_Key_Id (Data (Data'First .. Last));
            begin
               if List.Contains (Key_Id) then
                  Context.Decrypt_GPG_Secret (Data (Data'First .. Last));
                  exit when Context.Valid_Key;
               end if;
            end;
         end if;
      end loop;
      Context.Current := Context.First;
   end Load_Secrets;

   --  ------------------------------
   --  Get the password through the Getter operation.
   --  ------------------------------
   overriding
   procedure Get_Password (From   : in Context_Type;
                           Getter : not null
                           access procedure (Password : in Secret_Key)) is
   begin
      Getter (From.Current.Key);
   end Get_Password;

   --  ------------------------------
   --  Get the key and IV through the Getter operation.
   --  ------------------------------
   overriding
   procedure Get_Key (From   : in Context_Type;
                      Getter : not null
                      access procedure (Key : in Secret_Key;
                                        IV  : in Secret_Key)) is
   begin
      Getter (From.Current.Key, From.Current.IV);
   end Get_Key;

   --  ------------------------------
   --  Get the Key, IV and signature.
   --  ------------------------------
   overriding
   procedure Get_Keys (From : in Context_Type;
                       Key  : out Secret_Key;
                       IV   : out Secret_Key;
                       Sign : out Secret_Key) is
   begin
      Util.Encoders.Create (From.Data (POS_WALLET_KEY .. POS_WALLET_KEY_LAST), Key);
      Util.Encoders.Create (From.Data (POS_WALLET_IV .. POS_WALLET_IV_LAST), IV);
      Util.Encoders.Create (From.Data (POS_WALLET_SIGN .. POS_WALLET_SIGN_LAST), Sign);
   end Get_Keys;

   --  ------------------------------
   --  Get the key slot number associated with the GPG password.
   --  ------------------------------
   overriding
   function Get_Tag (From : in Context_Type) return Tag_Type is
   begin
      return From.Current.Tag;
   end Get_Tag;

   --  ------------------------------
   --  Returns true if the provider has a GPG password.
   --  ------------------------------
   overriding
   function Has_Password (From : in Context_Type) return Boolean is
   begin
      return From.Current /= null;
   end Has_Password;

   --  ------------------------------
   --  Move to the next GPG password.
   --  ------------------------------
   overriding
   procedure Next (From : in out Context_Type) is
   begin
      From.Current := From.Current.Next;
   end Next;

   --  ------------------------------
   --  Get the command to encrypt the secret for the given GPG user/keyid.
   --  ------------------------------
   function Get_Encrypt_Command (Context : in Context_Type;
                                 User    : in String) return String is
      use Ada.Strings.Fixed;

      USER_LABEL : constant String := "$USER";
      Cmd        : constant String := To_String (Context.Encrypt_Command);
      Result     : Unbounded_String;
      First      : Positive := Cmd'First;
      Pos        : Natural;
   begin
      loop
         Pos := Index (Cmd, USER_LABEL, First);
         if Pos = 0 then
            Append (Result, Cmd (First .. Cmd'Last));
            return To_String (Result);
         end if;
         Append (Result, Cmd (First .. Pos - 1));
         Append (Result, User);
         First := Pos + USER_LABEL'Length;
      end loop;
   end Get_Encrypt_Command;

   --  ------------------------------
   --  Decrypt the data array that was encrypted using GPG2.
   --  ------------------------------
   procedure Decrypt_GPG_Secret (Context : in out Context_Type;
                                 Data    : in Ada.Streams.Stream_Element_Array) is
      Proc   : Util.Processes.Process;
      Last   : Ada.Streams.Stream_Element_Offset := 0;
      Last2  : Ada.Streams.Stream_Element_Offset;
      Cmd    : constant String := To_String (Context.Decrypt_Command);
      Status : Natural;
   begin
      Log.Info ("Decrypt GPG secret using {0}", Cmd);

      Context.Data (POS_TAG .. POS_TAG_LAST) := Data (Data'First .. Data'First + 3);
      Last := POS_TAG_LAST;
      Util.Processes.Spawn (Proc    => Proc,
                            Command => Cmd,
                            Mode    => Util.Processes.READ_WRITE);

      Util.Processes.Get_Input_Stream (Proc).Write (Data (POS_LOCK_KEY .. Data'Last));
      Util.Processes.Get_Input_Stream (Proc).Close;
      while Last < Context.Data'Last loop
         Util.Processes.Get_Output_Stream (Proc).Read
           (Context.Data (Last + 1 .. Context.Data'Last), Last2);
         exit when Last2 = Last;
         Last := Last2;
      end loop;

      Util.Processes.Wait (Proc);
      Status := Util.Processes.Get_Exit_Status (Proc);
      Context.Valid_Key := Status = 0 and Last > 4;
      if Context.Valid_Key then
         Context.Create_Secret (Context.Data);
      elsif Status /= 0 then
         Log.Warn ("GPG decrypt command '{0}' terminated with exit code{1}", Cmd,
                   Natural'Image (Status));
      end if;
      Context.Data (POS_TAG .. POS_LOCK_IV_LAST) := (others => 0);

   exception
      when E : Util.Processes.Process_Error =>
         Log.Warn ("Cannot execute GPG decrypt command '{0}': {1}",
                   Cmd, Ada.Exceptions.Exception_Message (E));
         Context.Valid_Key := False;

   end Decrypt_GPG_Secret;

   --  ------------------------------
   --  Setup the command to be executed to encrypt the secret with GPG2.
   --  ------------------------------
   procedure Set_Encrypt_Command (Into    : in out Context_Type;
                                  Command : in String) is
   begin
      Into.Encrypt_Command := To_Unbounded_String (Command);
   end Set_Encrypt_Command;

   --  ------------------------------
   --  Setup the command to be executed to decrypt the secret with GPG2.
   --  ------------------------------
   procedure Set_Decrypt_Command (Into    : in out Context_Type;
                                  Command : in String) is
   begin
      Into.Decrypt_Command := To_Unbounded_String (Command);
   end Set_Decrypt_Command;

   --  ------------------------------
   --  Setup the command to be executed to get the list of available GPG secret keys.
   --  ------------------------------
   procedure Set_List_Key_Command (Into    : in out Context_Type;
                                   Command : in String) is
   begin
      Into.List_Key_Command := To_Unbounded_String (Command);
   end Set_List_Key_Command;

   overriding
   procedure Initialize (Context : in out Context_Type) is
   begin
      Context.Encrypt_Command := To_Unbounded_String (ENCRYPT_COMMAND);
      Context.Decrypt_Command := To_Unbounded_String (DECRYPT_COMMAND);
      Context.List_Key_Command := To_Unbounded_String (LIST_COMMAND);
   end Initialize;

   overriding
   procedure Finalize (Context : in out Context_Type) is
      procedure Free is
        new Ada.Unchecked_Deallocation (Object => Secret_Provider,
                                        Name   => Secret_Provider_Access);
   begin
      Context.Data := (others => 0);
      while Context.First /= null loop
         Context.Current := Context.First.Next;
         Free (Context.First);
         Context.First := Context.Current;
      end loop;
   end Finalize;

end Keystore.Passwords.GPG;
