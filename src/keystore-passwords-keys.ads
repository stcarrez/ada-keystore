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

package Keystore.Passwords.Keys is

   use type Ada.Streams.Stream_Element_Offset;

   type Key_Provider is limited interface;
   type Key_Provider_Access is access all Key_Provider'Class;

   --  Get the Key, IV and signature.
   procedure Get_Keys (From : in Key_Provider;
                       Key  : out Secret_Key;
                       IV   : out Secret_Key;
                       Sign : out Secret_Key) is abstract with
     Post'Class => Key.Length = 32 and IV.Length = 16 and Sign.Length = 32;

end Keystore.Passwords.Keys;
