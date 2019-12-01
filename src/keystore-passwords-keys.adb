-----------------------------------------------------------------------
--  keystore-passwords-keys -- Key provider
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
with Util.Encoders.SHA256;
with Util.Encoders.HMAC.SHA256;
package body Keystore.Passwords.Keys is

   type Raw_Key_Provider (Len : Key_Length) is limited new Key_Provider with record
      Password : Ada.Streams.Stream_Element_Array (1 .. Len);
   end record;
   type Raw_Key_Provider_Access is access all Raw_Key_Provider'Class;

   --  Get the Key, IV and signature.
   procedure Get_Keys (From : in Raw_Key_Provider;
                       Key  : out Secret_Key;
                       IV   : out Secret_Key;
                       Sign : out Secret_Key);

   --  ------------------------------
   --  Create a key, iv, sign provider from the string.
   --  ------------------------------
   function Create (Password : in String;
                    Length   : in Key_Length := DEFAULT_KEY_LENGTH)
                    return Key_Provider_Access is
      Result : Raw_Key_Provider_Access;
      Hash   : Util.Encoders.SHA256.Hash_Array;
   begin
      Result := new Raw_Key_Provider '(Len => Length, others => <>);
      Hash := Util.Encoders.HMAC.SHA256.Sign (Password, Password);

      for I in 1 .. Length loop
         Result.Password (I) := Hash (I mod Hash'Length);
         Util.Encoders.HMAC.SHA256.Sign (Hash, Hash, Hash);
      end loop;
      return Result.all'Access;
   end Create;

   function Create (Password : in Ada.Streams.Stream_Element_Array)
                    return Key_Provider_Access is
   begin
      return new Raw_Key_Provider '(Len      => Password'Length,
                                    Password => Password);
   end Create;

   --  ------------------------------
   --  Get the Key, IV and signature.
   --  ------------------------------
   overriding
   procedure Get_Keys (From : in Raw_Key_Provider;
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

end Keystore.Passwords.Keys;
