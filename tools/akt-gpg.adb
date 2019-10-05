-----------------------------------------------------------------------
--  akt-gpg -- GPG utilities
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
with Util.Streams;
with Util.Log.Loggers;
with Util.Encoders;
with Util.Processes;
with Keystore.Random;
package body AKT.GPG is

   use Ada.Strings.Unbounded;
   use type Ada.Streams.Stream_Element_Offset;
   use type Keystore.Header_Slot_Type;

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("AKT.GPG");

   --  ------------------------------
   --  Generate a secret to protect the keystore.
   --  ------------------------------
   procedure Generate_Secret (Context : in out Context_Type) is
      Rand : Keystore.Random.Generator;
   begin
      Rand.Generate (Context.Data);
   end Generate_Secret;

   --  ------------------------------
   --  Get the secret used to protect the keystore.
   --  ------------------------------
   function Get_Secret (Context : in Context_Type) return Keystore.Secret_Key is
   begin
      return Secret : Keystore.Secret_Key (Length => Context.Data'Length) do
         Util.Encoders.Create (Context.Data, Secret);
      end return;
   end Get_Secret;

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
   --  Unlock the keystore with one of the GPG key.
   --  ------------------------------
   procedure Unlock (Context : in out Context_Type;
                     Wallet  : in out Keystore.Files.Wallet_File;
                     Info    : in Keystore.Wallet_Info) is
      Data : Ada.Streams.Stream_Element_Array (1 .. 1024);
      Last : Ada.Streams.Stream_Element_Offset;
      Kind : Keystore.Header_Slot_Type;
   begin
      for Index in 1 .. Info.Header_Count loop
         Wallet.Get_Header_Data (Index, Kind, Data, Last);
         if Kind = Keystore.SLOT_KEY_GPG2 then
            declare
               Key : Keystore.Secret_Key :=
                 Context.Decrypt_GPG_Secret (Data (Data'First .. Last));
            begin
               Wallet.Unlock (Key);
            end;
         end if;
      end loop;
   end Unlock;

   --  ------------------------------
   --  Save the GPG secret by encrypting it using the user's GPG key and storing
   --  the encrypted data in the keystore data header.
   --  ------------------------------
   procedure Save_GPG_Secret (Context : in out Context_Type;
                              Wallet  : in out Keystore.Files.Wallet_File) is
      Data : constant Ada.Streams.Stream_Element_Array := Context.Encrypt_GPG_Secret;
   begin
      if Data'Length <= 1 then
         raise Keystore.Bad_Password;
         return;
      end if;
      Keystore.Files.Set_Header_Data (Wallet, 1, Keystore.SLOT_KEY_GPG2, Data);
   end Save_GPG_Secret;

   --  ------------------------------
   --  Decrypt the data array that was encrypted using GPG2.
   --  ------------------------------
   function Decrypt_GPG_Secret (Context : in Context_Type;
                                Data    : in Ada.Streams.Stream_Element_Array)
                                return Keystore.Secret_Key is
      Proc   : Util.Processes.Process;
      Result : Ada.Streams.Stream_Element_Array (1 .. MAX_DECRYPT_SIZE);
      Last   : Ada.Streams.Stream_Element_Offset := 0;
      Last2  : Ada.Streams.Stream_Element_Offset;
   begin
      Util.Processes.Spawn (Proc    => Proc,
                            Command => To_String (Context.Decrypt_Command),
                            Mode    => Util.Processes.READ_WRITE);

      Util.Processes.Get_Input_Stream (Proc).Write (Data);
      Util.Processes.Get_Input_Stream (Proc).Close;
      while Last < Result'Last loop
         Util.Processes.Get_Output_Stream (Proc).Read (Result (Last + 1 .. Result'Last), Last2);
         exit when Last2 = Last;
         Last := Last2;
      end loop;

      Util.Processes.Wait (Proc);
      if Util.Processes.Get_Exit_Status (Proc) /= 0 or Last <= 1 then
         return S : Keystore.Secret_Key (Length => 1);
      end if;
      return Key : Keystore.Secret_Key (Length => Last) do
         Util.Encoders.Create (Result (1 .. Last), Key);
      end return;
   end Decrypt_GPG_Secret;

   overriding
   procedure Initialize (Context : in out Context_Type) is
   begin
      Context.Encrypt_Command := To_Unbounded_String (AKT.GPG.ENCRYPT_COMMAND);
      Context.Decrypt_Command := To_Unbounded_String (AKT.GPG.DECRYPT_COMMAND);
   end Initialize;

   overriding
   procedure Finalize (Context : in out Context_Type) is
   begin
      Context.Data := (others => 0);
   end Finalize;

end AKT.GPG;
