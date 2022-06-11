-----------------------------------------------------------------------
--  keystore-passwords-gpg -- Password protected by GPG
--  Copyright (C) 2019, 2022 Stephane Carrez
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
with Util.Strings.Sets;
with Keystore.Files;
with Keystore.Passwords.Keys;
private with Keystore.IO;
package Keystore.Passwords.GPG is

   MAX_ENCRYPT_SIZE : constant := 1024;

   LIST_COMMAND    : constant String := "gpg --list-secret-keys --with-colons --with-fingerprint";
   ENCRYPT_COMMAND : constant String := "gpg --encrypt --batch --yes -r $USER";
   DECRYPT_COMMAND : constant String := "gpg --decrypt --batch --yes --quiet";

   --  Extract the Key ID from the data content when it is encrypted by GPG2.
   function Extract_Key_Id (Data : in Ada.Streams.Stream_Element_Array) return String;

   type Context_Type is limited new Ada.Finalization.Limited_Controlled
     and Slot_Provider and Keys.Key_Provider with private;

   --  Get the list of GPG secret keys that could be capable for decrypting a content for us.
   procedure List_GPG_Secret_Keys (Context : in out Context_Type;
                                   List    : in out Util.Strings.Sets.Set);

   --  Create a secret to protect the keystore.
   procedure Create_Secret (Context : in out Context_Type);
   procedure Create_Secret (Context : in out Context_Type;
                            Image   : in Context_Type'Class);
   procedure Create_Secret (Context      : in out Context_Type;
                            Key_Provider : in Keys.Key_Provider'Class);

   --  Save the GPG secret by encrypting it using the user's GPG key and storing
   --  the encrypted data in the keystore data header.
   procedure Save_Secret (Context : in out Context_Type;
                          User    : in String;
                          Index   : in Keystore.Header_Slot_Index_Type;
                          Wallet  : in out Keystore.Files.Wallet_File);

   --  Load the GPG secrets stored in the keystore header.
   procedure Load_Secrets (Context : in out Context_Type;
                           Wallet  : in out Keystore.Files.Wallet_File);

   --  Get the password through the Getter operation.
   overriding
   procedure Get_Password (From   : in Context_Type;
                           Getter : not null
                           access procedure (Password : in Secret_Key));

   --  Get the key slot number associated with the GPG password.
   overriding
   function Get_Tag (From : in Context_Type) return Tag_Type;

   --  Returns true if the provider has a GPG password.
   overriding
   function Has_Password (From : in Context_Type) return Boolean;

   --  Move to the next GPG password.
   overriding
   procedure Next (From : in out Context_Type);

   --  Get the key and IV through the Getter operation.
   overriding
   procedure Get_Key (From   : in Context_Type;
                      Getter : not null access procedure (Key : in Secret_Key;
                                                          IV  : in Secret_Key));

   --  Get the Key, IV and signature.
   overriding
   procedure Get_Keys (From : in Context_Type;
                       Key  : out Secret_Key;
                       IV   : out Secret_Key;
                       Sign : out Secret_Key);

   --  Setup the command to be executed to encrypt the secret with GPG2.
   procedure Set_Encrypt_Command (Into    : in out Context_Type;
                                  Command : in String);

   --  Setup the command to be executed to decrypt the secret with GPG2.
   procedure Set_Decrypt_Command (Into    : in out Context_Type;
                                  Command : in String);

   --  Setup the command to be executed to get the list of available GPG secret keys.
   procedure Set_List_Key_Command (Into    : in out Context_Type;
                                   Command : in String);

private

   type Secret_Provider;
   type Secret_Provider_Access is access all Secret_Provider;

   type Secret_Provider is limited record
      Next   : Secret_Provider_Access;
      Tag    : Tag_Type;
      Key    : Secret_Key (Length => IO.SIZE_SECRET);
      IV     : Secret_Key (Length => IO.SIZE_IV);
   end record;

   --  Positions of values stored in the GPG encrypted data.
   POS_TAG              : constant := 1;
   POS_TAG_LAST         : constant := POS_TAG + 3;
   POS_LOCK_KEY         : constant := POS_TAG_LAST + 1;
   POS_LOCK_KEY_LAST    : constant := POS_LOCK_KEY + IO.SIZE_SECRET - 1;
   POS_LOCK_IV          : constant := POS_LOCK_KEY_LAST + 1;
   POS_LOCK_IV_LAST     : constant := POS_LOCK_IV + IO.SIZE_IV - 1;
   POS_WALLET_KEY       : constant := POS_LOCK_IV_LAST + 1;
   POS_WALLET_KEY_LAST  : constant := POS_WALLET_KEY + IO.SIZE_SECRET - 1;
   POS_WALLET_IV        : constant := POS_WALLET_KEY_LAST + 1;
   POS_WALLET_IV_LAST   : constant := POS_WALLET_IV + IO.SIZE_IV - 1;
   POS_WALLET_SIGN      : constant := POS_WALLET_IV_LAST + 1;
   POS_WALLET_SIGN_LAST : constant := POS_WALLET_SIGN + IO.SIZE_SECRET - 1;
   GPG_DATA_SIZE        : constant := 4 + IO.SIZE_SECRET * 3 + IO.SIZE_IV * 2;

   HEADER_KEY_SIZE : constant := IO.SIZE_SECRET + IO.SIZE_IV + IO.SIZE_SECRET;

   type Context_Type is limited new Ada.Finalization.Limited_Controlled
     and Slot_Provider and Keys.Key_Provider with record
      Current          : Secret_Provider_Access;
      First            : Secret_Provider_Access;
      Data             : Ada.Streams.Stream_Element_Array (1 .. GPG_DATA_SIZE);
      Size             : Ada.Streams.Stream_Element_Offset;
      Index            : Keystore.Header_Slot_Index_Type := 1;
      Encrypt_Command  : Ada.Strings.Unbounded.Unbounded_String;
      Decrypt_Command  : Ada.Strings.Unbounded.Unbounded_String;
      List_Key_Command : Ada.Strings.Unbounded.Unbounded_String;
      Valid_Key        : Boolean := False;
   end record;

   procedure Create_Secret (Context : in out Context_Type;
                            Data    : in Ada.Streams.Stream_Element_Array);

   procedure Decrypt_GPG_Secret (Context : in out Context_Type;
                                 Data    : in Ada.Streams.Stream_Element_Array);

   --  Get the command to encrypt the secret for the given GPG user/keyid.
   function Get_Encrypt_Command (Context : in Context_Type;
                                 User    : in String) return String;

   overriding
   procedure Initialize (Context : in out Context_Type);

   overriding
   procedure Finalize (Context : in out Context_Type);

end Keystore.Passwords.GPG;
