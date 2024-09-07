-----------------------------------------------------------------------
--  keystore-passwords-keys -- Key provider
--  Copyright (C) 2019, 2023 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with Util.Encoders.SHA256;
with Util.Encoders.HMAC.SHA256;
package body Keystore.Passwords.Keys is

   type Raw_Key_Provider (Len : Key_Length) is limited new Key_Provider
     and Internal_Key_Provider with record
      Password : Ada.Streams.Stream_Element_Array (1 .. Len);
   end record;
   type Raw_Key_Provider_Access is access all Raw_Key_Provider'Class;

   --  Get the Key, IV and signature.
   overriding
   procedure Get_Keys (From : in Raw_Key_Provider;
                       Key  : out Secret_Key;
                       IV   : out Secret_Key;
                       Sign : out Secret_Key);

   overriding
   procedure Save_Key (Provider : in Raw_Key_Provider;
                       Data     : out Ada.Streams.Stream_Element_Array);

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

      --  Cancel the warning: writable actual for "Data" overlaps with actual for "Into".
      pragma Warnings (Off);
      Hash := Util.Encoders.HMAC.SHA256.Sign (Password, Password);

      for I in 1 .. Length loop
         Result.Password (I) := Hash (I mod Hash'Length);
         Util.Encoders.HMAC.SHA256.Sign (Hash, Hash, Hash);
      end loop;
      pragma Warnings (On);

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

   overriding
   procedure Save_Key (Provider : in Raw_Key_Provider;
                       Data     : out Ada.Streams.Stream_Element_Array) is
   begin
      Data := Provider.Password;
   end Save_Key;

end Keystore.Passwords.Keys;
