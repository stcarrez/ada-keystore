-----------------------------------------------------------------------
--  keystore-passwords-files -- File based password provider
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with Keystore.Passwords.Keys;
package Keystore.Passwords.Files is

   MAX_FILE_SIZE           : constant := 1024;
   DEFAULT_KEY_FILE_LENGTH : constant := 32 + 16 + 32;

   --  Create a password provider that reads the file to build the password.
   --  The file must have the mode rw------- (600) and its owning directory
   --  the mode rwx------ (700).  The Bad_Password exception is raised if
   --  these rules are not verified.
   function Create (Path : in String) return Provider_Access;

   --  Create a key provider that reads the file.  The file is split in three parts
   --  the key, the IV, the signature which are extracted by using `Get_Keys`.
   function Create (Path : in String) return Keys.Key_Provider_Access;

   --  Generate a file that contains the keys.  Keys are generated using a random generator.
   --  The file is created with the mode rw------- (600) and the owning directory is forced
   --  to the mode rwx------ (700).
   function Generate (Path   : in String;
                      Length : in Key_Length := DEFAULT_KEY_FILE_LENGTH)
                      return Keys.Key_Provider_Access;

end Keystore.Passwords.Files;
