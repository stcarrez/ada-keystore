-----------------------------------------------------------------------
--  keystore-passwords-gpg -- Password protected by GPG
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
with Ada.Unchecked_Deallocation;
with Ada.Strings.Fixed;
with GNAT.Regpat;
with Util.Streams;
with Util.Log.Loggers;
with Util.Encoders;
with Util.Processes;
with Util.Streams.Texts;
with Util.Streams.Pipes;
with Keystore.Random;
package body Keystore.Passwords.GPG is

   use Ada.Streams;
   use Ada.Strings.Unbounded;

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Keystore.Passwords.GPG");

   function Get_Le_Long (Data : in Ada.Streams.Stream_Element_Array)
                         return Interfaces.Unsigned_32;

   --  Headers of GPG packet.
   GPG_RSA_2048 : constant Ada.Streams.Stream_Element_Array (1 .. 4)
     := (16#85#, 16#01#, 16#0C#, 16#03#);
   GPG_RSA_3072 : constant Ada.Streams.Stream_Element_Array (1 .. 4)
     := (16#85#, 16#01#, 16#8C#, 16#03#);
   GPG_RSA_3072b : constant Ada.Streams.Stream_Element_Array (1 .. 4)
     := (16#85#, 16#02#, 16#0C#, 16#03#);
   GPG_RSA_4096 : constant Ada.Streams.Stream_Element_Array (1 .. 4)
     := (16#85#, 16#04#, 16#0C#, 16#03#);

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
      if Data (Data'First .. Data'First + 3) /= GPG_RSA_2048
        and Data (Data'First .. Data'First + 3) /= GPG_RSA_3072
        and Data (Data'First .. Data'First + 3) /= GPG_RSA_3072b
        and Data (Data'First .. Data'First + 3) /= GPG_RSA_4096
      then
         return "";
      end if;
      L1 := Get_Le_Long (Data (Data'First + 4 .. Data'Last));
      L2 := Get_Le_Long (Data (Data'First + 8 .. Data'Last));
      return Encode.Encode_Unsigned_32 (L1) & Encode.Encode_Unsigned_32 (L2);
   end Extract_Key_Id;

   --  ------------------------------
   --  Get the list of GPG secret keys that could be capable for decrypting a content for us.
   --  ------------------------------
   procedure List_GPG_Secret_Keys (Context : in out Context_Type;
                                   List    : in out Util.Strings.Sets.Set) is
      procedure Parse (Line : in String);

      --  ssb:u:<key-size>:<key-algo>:<key-id>:<create-date>:<expire-date>:::::<e>:
      REGEX : constant String
        := "^(ssb|sec):u:[1-9][0-9][0-9][0-9]:[0-9]:([0-9a-fA-F]+):[0-9]+:[0-9]?:::::[esa]+::.*";

      Pattern : constant GNAT.Regpat.Pattern_Matcher := GNAT.Regpat.Compile (REGEX);

      procedure Parse (Line : in String) is
         Matches : GNAT.Regpat.Match_Array (0 .. 2);
      begin
         if not GNAT.Regpat.Match (Pattern, Line) then
            return;
         end if;
         GNAT.Regpat.Match (Pattern, Line, Matches);
         List.Include (Line (Matches (2).First .. Matches (2).Last));

      exception
         when others =>
            Log.Debug ("Unkown line: {0}", Line);
      end Parse;

      Command : constant String := To_String (Context.List_Key_Command);
      Pipe    : aliased Util.Streams.Pipes.Pipe_Stream;
      Reader  : Util.Streams.Texts.Reader_Stream;
   begin
      Pipe.Open (Command, Util.Processes.READ);
      Reader.Initialize (Pipe'Access, 4096);

      while not Reader.Is_Eof loop
         declare
            Line : Ada.Strings.Unbounded.Unbounded_String;
         begin
            Reader.Read_Line (Line);
            Parse (To_String (Line));
         end;
      end loop;
      Pipe.Close;
   end List_GPG_Secret_Keys;

   --  ------------------------------
   --  Create a secret to protect the keystore.
   --  ------------------------------
   procedure Create_Secret (Context : in out Context_Type) is
      Rand : Keystore.Random.Generator;
      P    : Secret_Provider_Access;
   begin
      Rand.Generate (Context.Data);
      P := new Secret_Provider '(Len    => Context.Data'Length,
                                 Slot   => 1,
                                 Next   => Context.First,
                                 others => <>);
      Context.First := P;
      Util.Encoders.Create (Context.Data, P.Secret);
      Context.Current := P;
   end Create_Secret;

   --  ------------------------------
   --  Save the GPG secret by encrypting it using the user's GPG key and storing
   --  the encrypted data in the keystore data header.
   --  ------------------------------
   procedure Save_Secret (Context : in out Context_Type;
                          User    : in String;
                          Wallet  : in out Keystore.Files.Wallet_File) is
      Cmd    : constant String := Context.Get_Encrypt_Command (User);
      Proc   : Util.Processes.Process;
      Result : Ada.Streams.Stream_Element_Array (1 .. MAX_ENCRYPT_SIZE);
      Last   : Ada.Streams.Stream_Element_Offset := 0;
      Last2  : Ada.Streams.Stream_Element_Offset;
   begin
      Log.Info ("Encrypt GPG secret using {0}", Cmd);

      Util.Processes.Spawn (Proc    => Proc,
                            Command => Cmd,
                            Mode    => Util.Processes.READ_WRITE);

      Util.Processes.Get_Input_Stream (Proc).Write (Context.Data);
      Util.Processes.Get_Input_Stream (Proc).Close;
      while Last < Result'Last loop
         Util.Processes.Get_Output_Stream (Proc).Read (Result (Last + 1 .. Result'Last), Last2);
         exit when Last2 = Last;
         Last := Last2;
      end loop;

      Util.Processes.Wait (Proc);
      if Util.Processes.Get_Exit_Status (Proc) /= 0 or Last <= 1 then
         raise Keystore.Bad_Password;
      end if;

      Keystore.Files.Set_Header_Data (Wallet, Context.Index,
                                      Keystore.SLOT_KEY_GPG2, Result (1 .. Last));
      Context.Index := Context.Index + 1;
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
      Getter (From.Current.Secret);
   end Get_Password;

   --  ------------------------------
   --  Get the key slot number associated with the GPG password.
   --  ------------------------------
   overriding
   function Get_Key_Slot (From : in Context_Type) return Key_Slot is
   begin
      return From.Current.Slot;
   end Get_Key_Slot;

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
   --  Encrypt the data array using GPG2 private key.
   --  ------------------------------
   function Encrypt_GPG_Secret (Context : in Context_Type)
                                return Ada.Streams.Stream_Element_Array is
      Proc   : Util.Processes.Process;
      Result : Ada.Streams.Stream_Element_Array (1 .. MAX_ENCRYPT_SIZE);
      Last   : Ada.Streams.Stream_Element_Offset := 0;
      Last2  : Ada.Streams.Stream_Element_Offset;
      Cmd    : constant String := To_String (Context.Encrypt_Command);
   begin
      Log.Info ("Encrypt GPG secret using {0}", Cmd);

      Util.Processes.Spawn (Proc    => Proc,
                            Command => Cmd,
                            Mode    => Util.Processes.READ_WRITE);

      Util.Processes.Get_Input_Stream (Proc).Write (Context.Data);
      Util.Processes.Get_Input_Stream (Proc).Close;
      while Last < Result'Last loop
         Util.Processes.Get_Output_Stream (Proc).Read (Result (Last + 1 .. Result'Last), Last2);
         exit when Last2 = Last;
         Last := Last2;
      end loop;

      Util.Processes.Wait (Proc);
      if Util.Processes.Get_Exit_Status (Proc) /= 0 or Last <= 1 then
         return Result (1 .. 0);
      end if;
      return Result (1 .. Last);
   end Encrypt_GPG_Secret;

   --  ------------------------------
   --  Decrypt the data array that was encrypted using GPG2.
   --  ------------------------------
   procedure Decrypt_GPG_Secret (Context : in out Context_Type;
                                 Data    : in Ada.Streams.Stream_Element_Array) is
      Proc   : Util.Processes.Process;
      Last   : Ada.Streams.Stream_Element_Offset := 0;
      Last2  : Ada.Streams.Stream_Element_Offset;
      Cmd    : constant String := To_String (Context.Decrypt_Command);
   begin
      Log.Info ("Decrypt GPG secret using {0}", Cmd);
      Util.Processes.Spawn (Proc    => Proc,
                            Command => Cmd,
                            Mode    => Util.Processes.READ_WRITE);

      Util.Processes.Get_Input_Stream (Proc).Write (Data);
      Util.Processes.Get_Input_Stream (Proc).Close;
      while Last < Context.Data'Last loop
         Util.Processes.Get_Output_Stream (Proc).Read
           (Context.Data (Last + 1 .. Context.Data'Last), Last2);
         exit when Last2 = Last;
         Last := Last2;
      end loop;

      Util.Processes.Wait (Proc);
      Context.Valid_Key := Util.Processes.Get_Exit_Status (Proc) = 0 and Last > 1;
      if Context.Valid_Key then
         Context.First := new Secret_Provider '(Len    => Last,
                                                Slot   => 1,
                                                Next   => Context.First,
                                                others => <>);
         Util.Encoders.Create (Context.Data (1 .. Last), Context.First.Secret);
      end if;
      Context.Data := (others => 0);
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
