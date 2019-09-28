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
with Ada.Streams;
with Ada.Strings.Unbounded;
with Ada.Finalization;
with Keystore;
with Keystore.Files;
package AKT.GPG is

   MAX_ENCRYPT_SIZE : constant := 1024;
   MAX_DECRYPT_SIZE : constant := 256;

   ENCRYPT_COMMAND : constant String := "gpg2 --encrypt --batch --yes";
   DECRYPT_COMMAND : constant String := "gpg2 --decrypt --batch --yes --quiet";

   type Context_Type is limited new Ada.Finalization.Limited_Controlled with record
      Data            : Ada.Streams.Stream_Element_Array (1 .. MAX_DECRYPT_SIZE);
      Size            : Ada.Streams.Stream_Element_Offset;
      Encrypt_Command : Ada.Strings.Unbounded.Unbounded_String;
      Decrypt_Command : Ada.Strings.Unbounded.Unbounded_String;
   end record;

   --  Generate a secret to protect the keystore.
   procedure Generate_Secret (Context : in out Context_Type);

   --  Get the secret used to protect the keystore.
   function Get_Secret (Context : in Context_Type) return Keystore.Secret_Key;

   --  Encrypt the data array using GPG2 private key.
   function Encrypt_GPG_Secret (Context : in Context_Type)
                                return Ada.Streams.Stream_Element_Array;

   --  Decrypt the data array that was encrypted using GPG2.
   function Decrypt_GPG_Secret (Context : in Context_Type;
                                Data    : in Ada.Streams.Stream_Element_Array)
                                return Keystore.Secret_Key with
     Pre => Data'Length < MAX_ENCRYPT_SIZE;

   --  Save the GPG secret by encrypting it using the user's GPG key and storing
   --  the encrypted data in the keystore data header.
   procedure Save_GPG_Secret (Context : in out Context_Type;
                              Wallet  : in out Keystore.Files.Wallet_File);

   --  Unlock the keystore with one of the GPG key.
   procedure Unlock (Context : in out Context_Type;
                     Wallet  : in out Keystore.Files.Wallet_File;
                     Info    : in Keystore.Wallet_Info);

   overriding
   procedure Initialize (Context : in out Context_Type);

   overriding
   procedure Finalize (Context : in out Context_Type);

end AKT.GPG;
