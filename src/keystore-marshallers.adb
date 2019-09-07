-----------------------------------------------------------------------
--  keystore-marshallers -- Data marshaller for the keystore
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
with Util.Encoders.HMAC.SHA256;

package body Keystore.Marshallers is

   use Interfaces;

   --  ------------------------------
   --  Set the block header with the tag and wallet identifier.
   --  ------------------------------
   procedure Set_Header (Into : in out Marshaller;
                         Tag  : in Interfaces.Unsigned_16;
                         Id   : in Keystore.Wallet_Identifier) is
   begin
      Into.Pos := BT_HEADER_START;
      Put_Unsigned_16 (Into, Tag);
      Put_Unsigned_16 (Into, 0);
      Put_Unsigned_32 (Into, Interfaces.Unsigned_32 (Id));
      Put_Unsigned_32 (Into, 0);
      Put_Unsigned_32 (Into, 0);
   end Set_Header;

   procedure Put_Unsigned_16 (Into  : in out Marshaller;
                              Value : in Interfaces.Unsigned_16) is
      Pos : constant Block_Index := Into.Pos;
      Buf : constant Buffers.Buffer_Accessor := Into.Buffer.Data.Value;
   begin
      Into.Pos := Into.Pos + 2;
      Buf.Data (Pos) := Stream_Element (Shift_Right (Value, 8));
      Buf.Data (Pos + 1) := Stream_Element (Value and 16#0ff#);
   end Put_Unsigned_16;

   procedure Put_Unsigned_32 (Into  : in out Marshaller;
                              Value : in Interfaces.Unsigned_32) is
      Pos : constant Block_Index := Into.Pos;
      Buf : constant Buffers.Buffer_Accessor := Into.Buffer.Data.Value;
   begin
      Into.Pos := Into.Pos + 4;
      Buf.Data (Pos) := Stream_Element (Shift_Right (Value, 24));
      Buf.Data (Pos + 1) := Stream_Element (Shift_Right (Value, 16) and 16#0ff#);
      Buf.Data (Pos + 2) := Stream_Element (Shift_Right (Value, 8) and 16#0ff#);
      Buf.Data (Pos + 3) := Stream_Element (Value and 16#0ff#);
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

   procedure Put_Block_Index (Into  : in out Marshaller;
                              Value : in Block_Index) is
   begin
      Put_Unsigned_16 (Into, Interfaces.Unsigned_16 (Value));
   end Put_Block_Index;

   procedure Put_String (Into  : in out Marshaller;
                         Value : in String) is
      Pos : Block_Index;
      Buf : constant Buffers.Buffer_Accessor := Into.Buffer.Data.Value;
   begin
      Put_Unsigned_16 (Into, Value'Length);
      Pos := Into.Pos;
      Into.Pos := Into.Pos + Value'Length;
      for C of Value loop
         Buf.Data (Pos) := Character'Pos (C);
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

   procedure Put_Storage_Block (Into  : in out Marshaller;
                                Value : in Buffers.Storage_Block) is
   begin
      Put_Unsigned_32 (Into, Interfaces.Unsigned_32 (Value.Storage));
      Put_Unsigned_32 (Into, Interfaces.Unsigned_32 (Value.Block));
   end Put_Storage_Block;

   procedure Put_Secret (Into        : in out Marshaller;
                         Value       : in Secret_Key;
                         Protect_Key : in Secret_Key;
                         Protect_IV  : in Secret_Key) is
      Cipher_Key : Util.Encoders.AES.Encoder;
      Last       : Stream_Element_Offset;
      Buf        : constant Buffers.Buffer_Accessor := Into.Buffer.Data.Value;
      IV         : constant Util.Encoders.AES.Word_Block_Type
        := (others => Interfaces.Unsigned_32 (Into.Buffer.Block.Block));
   begin
      Cipher_Key.Set_Key (Protect_Key, Util.Encoders.AES.CBC);
      Cipher_Key.Set_IV (Protect_IV, IV);
      Cipher_Key.Set_Padding (Util.Encoders.AES.NO_PADDING);

      --  Encrypt the key into the key-slot using the PBKDF2 protection key.
      Last := Into.Pos + Block_Index (Value.Length) - 1;
      Cipher_Key.Encrypt_Secret (Secret  => Value,
                                 Into    => Buf.Data (Into.Pos .. Last));
      Into.Pos := Last + 1;
   end Put_Secret;

   procedure Put_HMAC_SHA256 (Into    : in out Marshaller;
                              Key     : in Secret_Key;
                              Content : in Ada.Streams.Stream_Element_Array) is
      Pos : constant Block_Index := Into.Pos;
      Buf : constant Buffers.Buffer_Accessor := Into.Buffer.Data.Value;
   begin
      Into.Pos := Into.Pos + BT_HMAC_HEADER_SIZE;

      --  Make HMAC-SHA256 signature of the data content before encryption.
      Util.Encoders.HMAC.SHA256.Sign (Key    => Key,
                                      Data   => Content,
                                      Result => Buf.Data (Pos .. Into.Pos - 1));
   end Put_HMAC_SHA256;

   function Get_Unsigned_16 (From  : in out Marshaller) return Interfaces.Unsigned_16 is
      Pos : constant Block_Index := From.Pos;
      Buf : constant Buffers.Buffer_Accessor := From.Buffer.Data.Value;
   begin
      From.Pos := From.Pos + 2;
      return Shift_Left (Unsigned_16 (Buf.Data (Pos)), 8) or
        Unsigned_16 (Buf.Data (Pos + 1));
   end Get_Unsigned_16;

   function Get_Unsigned_32 (From  : in out Marshaller) return Interfaces.Unsigned_32 is
      Pos : constant Block_Index := From.Pos;
      Buf : constant Buffers.Buffer_Accessor := From.Buffer.Data.Value;
   begin
      From.Pos := From.Pos + 4;
      return Shift_Left (Unsigned_32 (Buf.Data (Pos)), 24) or
        Shift_Left (Unsigned_32 (Buf.Data (Pos + 1)), 16) or
        Shift_Left (Unsigned_32 (Buf.Data (Pos + 2)), 8) or
        Unsigned_32 (Buf.Data (Pos + 3));
   end Get_Unsigned_32;

   function Get_Unsigned_64 (From  : in out Marshaller) return Interfaces.Unsigned_64 is
      High : constant Interfaces.Unsigned_32 := Get_Unsigned_32 (From);
      Low  : constant Interfaces.Unsigned_32 := Get_Unsigned_32 (From);
   begin
      return Shift_Left (Unsigned_64 (High), 32) or Unsigned_64 (Low);
   end Get_Unsigned_64;

   function Get_Storage_Block (From : in out Marshaller) return Buffers.Storage_Block is
      Storage : constant Interfaces.Unsigned_32 := Get_Unsigned_32 (From);
      Block   : constant Interfaces.Unsigned_32 := Get_Unsigned_32 (From);
   begin
      return Buffers.Storage_Block '(Storage => Buffers.Storage_Identifier (Storage),
                                     Block   => Block_Number (Block));
   end Get_Storage_Block;

   function Get_String (From   : in out Marshaller;
                        Length : in Natural) return String is
      Result : String (1 .. Length);
      Pos    : Block_Index := From.Pos;
      Buf    : constant Buffers.Buffer_Accessor := From.Buffer.Data.Value;
   begin
      From.Pos := From.Pos + Block_Index (Length);
      for I in Result'Range loop
         Result (I) := Character'Val (Buf.Data (Pos));
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
                         Protect_Key : in Secret_Key;
                         Protect_IV  : in Secret_Key) is
      Decipher_Key  : Util.Encoders.AES.Decoder;
      Last          : Stream_Element_Offset;
      Buf           : constant Buffers.Buffer_Accessor := From.Buffer.Data.Value;
      IV            : constant Util.Encoders.AES.Word_Block_Type
        := (others => Interfaces.Unsigned_32 (From.Buffer.Block.Block));
   begin
      Decipher_Key.Set_Key (Protect_Key, Util.Encoders.AES.CBC);
      Decipher_Key.Set_IV (Protect_IV, IV);
      Decipher_Key.Set_Padding (Util.Encoders.AES.NO_PADDING);

      Last := From.Pos + Block_Index (Secret.Length) - 1;
      Decipher_Key.Decrypt_Secret (Data   => Buf.Data (From.Pos .. Last),
                                   Secret => Secret);
      From.Pos := Last + 1;
   end Get_Secret;

   procedure Skip (From  : in out Marshaller;
                   Count : in Block_Index) is
   begin
      From.Pos := From.Pos + Count;
   end Skip;

end Keystore.Marshallers;
