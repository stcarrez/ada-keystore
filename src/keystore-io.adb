-----------------------------------------------------------------------
--  keystore-ios -- IO low level operation for the keystore
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
with Interfaces.C;
with Ada.Calendar.Conversions;
with Util.Log.Loggers;
with Util.Encoders.SHA256;
with Util.Encoders.HMAC.SHA256;
with Keystore.Logs;

--  Generic Block header
--  +------------------+
--  | Block HMAC-256   | 32b
--  +------------------+
--  | Block type       | 4b
--  | Wallet id        | 4b
--  | PAD 0            | 4b
--  | PAD 0            | 4b
--  +------------------+
--  | ...AES-CTR...    | B
--  +------------------+
--
--  Free block
--  +------------------+
--  | PAD 0            | 32b
--  +------------------+
--  | 00 00 00 00      | 4b
--  | 00 00 00 00      | 4b
--  | Next free block  | 4b
--  | PAD 0            | 4b
--  +------------------+
--  | Free block ID    | 4b
--  +------------------+
--  | ...              |
--  +------------------+
--  | PAD 0            |
--  +------------------+
--
--  Wallet repository encrypted with Wallet id AES-CTR key
--  +------------------+
--  | Block HMAC-256   | 32b
--  +------------------+
--  | 02 02 02 02      | 4b
--  | Wallet id        | 4b
--  | PAD 0            | 4b
--  | PAD 0            | 4b
--  +------------------+
--  | Next block ID    | 4b  Block number for next repository
--  +------------------+
--  | Data block count | 2b
--  +------------------+
--  | Data block ID    | 4b
--  | Data header size | 2b
--  +------------------+
--  | ...              |

package body Keystore.IO is

   use Interfaces;

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Keystore.IO");

   --  ------------------------------
   --  Read the block from the wallet IO stream and decrypt the block content using
   --  the decipher object.  The decrypted content is stored in the marshaller which
   --  is ready to read the start of the block header.
   --  ------------------------------
   procedure Read (Stream       : in out Wallet_Stream'Class;
                   Block        : in Block_Number;
                   Decrypt_Size : in Block_Index := BT_DATA_LENGTH;
                   Decipher     : in out Util.Encoders.AES.Decoder;
                   Sign         : in Stream_Element_Array;
                   Into         : in out Marshaller) is

      procedure Read (Data : in Block_Type);

      procedure Read (Data : in Block_Type) is
         Last     : Stream_Element_Offset;
         Encoded  : Stream_Element_Offset;
         Hash     : Util.Encoders.SHA256.Hash_Array;
         Last_Pos : constant Stream_Element_Offset := BT_DATA_START + Decrypt_Size - 1;
         Context  : Util.Encoders.HMAC.SHA256.Context;
      begin
         Into.Data (Into.Data'First .. BT_DATA_START - 1)
           := Data (Data'First .. BT_DATA_START - 1);
         Log.Info ("Decrypt {0} .. {1}", Stream_Element_Offset'Image (BT_DATA_START),
                   Stream_Element_Offset'Image (Last_Pos));

         --  Decrypt the Size bytes
         Decipher.Transform (Data    => Data (BT_DATA_START .. Last_Pos),
                             Into    => Into.Data (BT_DATA_START .. Last_Pos),
                             Last    => Last,
                             Encoded => Encoded);
         Decipher.Finish (Into => Into.Data (Last + 1 .. Last_Pos),
                          Last => Last);
         if Encoded - 1 /= Last_Pos or Last /= Last_Pos then
            Keystore.Logs.Warn (Log, "Bloc{0} decryption failed", Block);
            raise Invalid_Block;
         end if;
         if Last_Pos < Into.Data'Last then
            Into.Data (Last_Pos + 1 .. Into.Data'Last) := Data (Last_Pos + 1 .. Data'Last);
         end if;

         Keystore.Logs.Debug (Log, "Dump block{0} after AES decrypt", Block);
         Keystore.Logs.Dump (Log, Into.Data (BT_DATA_START .. BT_DATA_START + 95));
         Keystore.Logs.Debug (Log, "...", 1);
         Keystore.Logs.Dump (Log, Into.Data (Into.Data'Last - 100 .. Into.Data'Last));

         --  Make HMAC-SHA256 signature of the block excluding the block hash mac.
         Util.Encoders.HMAC.SHA256.Set_Key (Context, Sign);
         Util.Encoders.HMAC.SHA256.Update (Context, Into.Data (BT_HEADER_START .. Last_Pos));
         if Last_Pos /= Into.Data'Last then
            Util.Encoders.HMAC.SHA256.Update (Context, Into.Data (Last_Pos + 1 .. Into.Data'Last));
         end if;
         Util.Encoders.HMAC.SHA256.Finish (Context, Hash);

         --  Check that the block hash mac matches our hash.
         if Hash /= Into.Data (Into.Data'First .. BT_HMAC_HEADER_SIZE) then
            Keystore.Logs.Warn (Log, "Block{0} HMAC-256 is invalid", Block);
            raise Invalid_Block;
         end if;
         Into.Pos := BT_HEADER_START;
      end Read;

   begin
      Keystore.Logs.Debug (Log, "Read block{0}", Block);

      Stream.Read (Block, Read'Access);
   end Read;

   --  ------------------------------
   --  Write the block in the wallet IO stream.  Encrypt the block data using the
   --  cipher object.  Sign the header and encrypted data using HMAC-256 and the
   --  given signature.
   --  ------------------------------
   procedure Write (Stream       : in out Wallet_Stream'Class;
                    Block        : in Block_Number;
                    Encrypt_Size : in Block_Index := BT_DATA_LENGTH;
                    Cipher       : in out Util.Encoders.AES.Encoder;
                    Sign         : in Stream_Element_Array;
                    From         : in Marshaller) is

      procedure Write (Data : out Block_Type);

      procedure Write (Data : out Block_Type) is
         Last     : Stream_Element_Offset;
         Encoded  : Stream_Element_Offset;
         Last_Pos : constant Stream_Element_Offset := BT_DATA_START + Encrypt_Size - 1;
      begin
         Log.Info ("Encrypt {0} .. {1}", Stream_Element_Offset'Image (BT_DATA_START),
                   Stream_Element_Offset'Image (Last_Pos));

         Data (BT_HEADER_START .. BT_DATA_START - 1)
           := From.Data (BT_HEADER_START .. BT_DATA_START - 1);
         Cipher.Transform (Data    => From.Data (BT_DATA_START .. Last_Pos),
                           Into    => Data (BT_DATA_START .. Last_Pos),
                           Last    => Last,
                           Encoded => Encoded);
         Log.Info ("Last={0} Encoded={0}",
                   Stream_Element_Offset'Image (Last),
                   Stream_Element_Offset'Image (Encoded));
         if Last_Pos < Data'Last then
            Data (Last_Pos + 1 .. Data'Last) := From.Data (Last_Pos + 1 .. Data'Last);
         end if;

         Keystore.Logs.Debug (Log, "Dump data block{0} before AES and write", Block);
         Keystore.Logs.Dump (Log, From.Data (BT_DATA_START .. BT_DATA_START + 95));
         Keystore.Logs.Debug (Log, "...", 1);
         Keystore.Logs.Dump (Log, From.Data (From.Data'Last - 100 .. From.Data'Last));

         --  Make HMAC-SHA256 signature of the block excluding the block hash mac.
         Util.Encoders.HMAC.SHA256.Sign (Key    => Sign,
                                         Data   => From.Data (BT_HEADER_START .. Data'Last),
                                         Result => Data (Data'First .. BT_HMAC_HEADER_SIZE));
      end Write;

   begin
      Stream.Write (Block, Write'Access);
   end Write;

   --  ------------------------------
   --  Set the block header with the tag and wallet identifier.
   --  ------------------------------
   procedure Set_Header (Into : in out Marshaller;
                         Tag  : in Interfaces.Unsigned_32;
                         Id   : in Interfaces.Unsigned_32) is
   begin
      Into.Pos := BT_HEADER_START;
      Put_Unsigned_32 (Into, Tag);
      Put_Unsigned_32 (Into, Id);
      Put_Unsigned_32 (Into, 0);
      Put_Unsigned_32 (Into, 0);
   end Set_Header;

   procedure Put_Unsigned_16 (Into  : in out Marshaller;
                              Value : in Interfaces.Unsigned_16) is
      Pos : constant Block_Index := Into.Pos;
   begin
      Into.Pos := Into.Pos + 2;
      Into.Data (Pos) := Stream_Element (Shift_Right (Value, 8));
      Into.Data (Pos + 1) := Stream_Element (Value and 16#0ff#);
   end Put_Unsigned_16;

   procedure Put_Unsigned_32 (Into  : in out Marshaller;
                              Value : in Interfaces.Unsigned_32) is
      Pos : constant Block_Index := Into.Pos;
   begin
      Into.Pos := Into.Pos + 4;
      Into.Data (Pos) := Stream_Element (Shift_Right (Value, 24));
      Into.Data (Pos + 1) := Stream_Element (Shift_Right (Value, 16) and 16#0ff#);
      Into.Data (Pos + 2) := Stream_Element (Shift_Right (Value, 8) and 16#0ff#);
      Into.Data (Pos + 3) := Stream_Element (Value and 16#0ff#);
   end Put_Unsigned_32;

   procedure Put_Unsigned_64 (Into  : in out Marshaller;
                              Value : in Interfaces.Unsigned_64) is
   begin
      Put_Unsigned_32 (Into, Unsigned_32 (Shift_Right (Value, 32)));
      Put_Unsigned_32 (Into, Unsigned_32 (Value and 16#0ffffffff#));
   end Put_Unsigned_64;

   procedure Put_Kind (Into  : in out Marshaller;
                       Value : in Entry_Type) is
   begin
      case Value is
         when T_INVALID =>
            Put_Unsigned_16 (Into, 0);

         when T_STRING =>
            Put_Unsigned_16 (Into, 1);

         when T_BINARY =>
            Put_Unsigned_16 (Into, 2);

         when T_WALLET =>
            Put_Unsigned_16 (Into, 3);

      end case;
   end Put_Kind;

   procedure Put_Block_Number (Into  : in out Marshaller;
                               Value : in Block_Number) is
   begin
      Put_Unsigned_32 (Into, Interfaces.Unsigned_32 (Value));
   end Put_Block_Number;

   procedure Put_String (Into  : in out Marshaller;
                         Value : in String) is
      Pos : Block_Index;
   begin
      Put_Unsigned_16 (Into, Value'Length);
      Pos := Into.Pos;
      Into.Pos := Into.Pos + Value'Length;
      for C of Value loop
         Into.Data (Pos) := Character'Pos (C);
         Pos := Pos + 1;
      end loop;
   end Put_String;

   procedure Put_Date (Into  : in out Marshaller;
                       Value : in Ada.Calendar.Time) is
      Unix_Time : Interfaces.C.long;
   begin
      Unix_Time := Ada.Calendar.Conversions.To_Unix_Time (Value);
      Put_Unsigned_64 (Into, Unsigned_64 (Unix_Time));
   end Put_Date;

   procedure Put_Secret (Into        : in out Marshaller;
                         Value       : in Secret_Key;
                         Protect_Key : in Secret_Key) is
      Cipher_Key  : Util.Encoders.AES.Encoder;
      Last        : Stream_Element_Offset;
   begin
      Cipher_Key.Set_Key (Protect_Key, Util.Encoders.AES.CBC);
      Cipher_Key.Set_Padding (Util.Encoders.AES.NO_PADDING);

      --  Encrypt the key into the key-slot using the PBKDF2 protection key.
      Last := Into.Pos + IO.Block_Index (Value.Length) - 1;
      Cipher_Key.Encrypt_Secret (Secret  => Value,
                                 Into    => Into.Data (Into.Pos .. Last));
      Into.Pos := Last + 1;
   end Put_Secret;

   procedure Put_Data (Into  : in out Marshaller;
                       Value : in Util.Encoders.AES.Word_Block_Type) is
   begin
      for V of Value loop
         Put_Unsigned_32 (Into, V);
      end loop;
   end Put_Data;

   procedure Put_HMAC_SHA256 (Into    : in out Marshaller;
                              Key     : in Ada.Streams.Stream_Element_Array;
                              Content : in Ada.Streams.Stream_Element_Array) is
      Pos : constant Block_Index := Into.Pos;
   begin
      Into.Pos := Into.Pos + BT_HMAC_HEADER_SIZE;

      --  Make HMAC-SHA256 signature of the data content before encryption.
      Util.Encoders.HMAC.SHA256.Sign (Key    => Key,
                                      Data   => Content,
                                      Result => Into.Data (Pos .. Into.Pos - 1));
   end Put_HMAC_SHA256;

   function Get_Unsigned_16 (From  : in out Marshaller) return Interfaces.Unsigned_16 is
      Pos : constant Block_Index := From.Pos;
   begin
      From.Pos := From.Pos + 2;
      return Shift_Left (Unsigned_16 (From.Data (Pos)), 8) or
        Unsigned_16 (From.Data (Pos + 1));
   end Get_Unsigned_16;

   function Get_Unsigned_32 (From  : in out Marshaller) return Interfaces.Unsigned_32 is
      Pos : constant Block_Index := From.Pos;
   begin
      From.Pos := From.Pos + 4;
      return Shift_Left (Unsigned_32 (From.Data (Pos)), 24) or
        Shift_Left (Unsigned_32 (From.Data (Pos + 1)), 16) or
        Shift_Left (Unsigned_32 (From.Data (Pos + 2)), 8) or
        Unsigned_32 (From.Data (Pos + 3));
   end Get_Unsigned_32;

   function Get_Unsigned_64 (From  : in out Marshaller) return Interfaces.Unsigned_64 is
      High : constant Interfaces.Unsigned_32 := Get_Unsigned_32 (From);
      Low  : constant Interfaces.Unsigned_32 := Get_Unsigned_32 (From);
   begin
      return Shift_Left (Unsigned_64 (High), 32) or Unsigned_64 (Low);
   end Get_Unsigned_64;

   function Get_String (From   : in out Marshaller;
                        Length : in Natural) return String is
      Result : String (1 .. Length);
      Pos    : Block_Index := From.Pos;
   begin
      From.Pos := From.Pos + Block_Index (Length);
      for I in Result'Range loop
         Result (I) := Character'Val (From.Data (Pos));
         Pos := Pos + 1;
      end loop;
      return Result;
   end Get_String;

   function Get_Date (From : in out Marshaller) return Ada.Calendar.Time is
      Unix_Time : constant Unsigned_64 := Get_Unsigned_64 (From);
   begin
      return Ada.Calendar.Conversions.To_Ada_Time (Interfaces.C.long (Unix_Time));
   end Get_Date;

   function Get_Kind (From : in out Marshaller) return Entry_Type is
      Value : constant Unsigned_16 := Get_Unsigned_16 (From);
   begin
      case Value is
         when 0 =>
            return T_INVALID;

         when 1 =>
            return T_STRING;

         when 2 =>
            return T_BINARY;

         when 3 =>
            return T_WALLET;

         when others =>
            return T_INVALID;

      end case;
   end Get_Kind;

   procedure Get_Secret (From        : in out Marshaller;
                         Secret      : out Secret_Key;
                         Protect_Key : in Secret_Key) is
      Decipher_Key  : Util.Encoders.AES.Decoder;
      Last          : Stream_Element_Offset;
   begin
      Decipher_Key.Set_Key (Protect_Key, Util.Encoders.AES.CBC);
      Decipher_Key.Set_Padding (Util.Encoders.AES.NO_PADDING);

      Last := From.Pos + IO.Block_Index (Secret.Length) - 1;
      Decipher_Key.Decrypt_Secret (Data   => From.Data (From.Pos .. Last),
                                   Secret => Secret);
      From.Pos := Last + 1;
   end Get_Secret;

   procedure Get_Data (From  : in out Marshaller;
                       Value : out Ada.Streams.Stream_Element_Array) is
   begin
      Value := From.Data (From.Pos .. From.Pos + Value'Length - 1);
      From.Pos := From.Pos + Value'Length;
   end Get_Data;

   procedure Get_Data (From  : in out Marshaller;
                       Value : out Util.Encoders.AES.Word_Block_Type) is
   begin
      for I in Value'Range loop
         Value (I) := Get_Unsigned_32 (From);
      end loop;
   end Get_Data;

   procedure Skip (From  : in out Marshaller;
                   Count : in Block_Index) is
   begin
      From.Pos := From.Pos + Count;
   end Skip;

end Keystore.IO;
