-----------------------------------------------------------------------
--  keystore-marshallers -- Data marshaller for the keystore
--  Copyright (C) 2019, 2020, 2025 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with Interfaces.C;
with Ada.Calendar.Conversions;
with Util.Encoders.HMAC.SHA256;
with Util.Encoders.AES;

package body Keystore.Marshallers is

   use Interfaces;

   --  ------------------------------
   --  Set the block header with the tag and wallet identifier.
   --  ------------------------------
   procedure Set_Header (Into : in out Marshaller;
                         Tag  : in Interfaces.Unsigned_16;
                         Id   : in Keystore.Wallet_Identifier) is
      Buf : constant Buffers.Buffer_Accessor := Into.Buffer.Data.Value;
   begin
      Into.Pos := Block_Index'First + 1;
      Buf.Data (Block_Index'First) := Stream_Element (Shift_Right (Tag, 8));
      Buf.Data (Block_Index'First + 1) := Stream_Element (Tag and 16#0ff#);
      Put_Unsigned_16 (Into, 0);
      Put_Unsigned_32 (Into, Interfaces.Unsigned_32 (Id));
      Put_Unsigned_32 (Into, 0);
      Put_Unsigned_32 (Into, 0);
   end Set_Header;

   procedure Set_Header (Into  : in out Marshaller;
                         Value : in Interfaces.Unsigned_32) is
      Buf : constant Buffers.Buffer_Accessor := Into.Buffer.Data.Value;
   begin
      Buf.Data (Block_Index'First) := Stream_Element (Shift_Right (Value, 24));
      Buf.Data (Block_Index'First + 1) := Stream_Element (Shift_Right (Value, 16) and 16#0ff#);
      Buf.Data (Block_Index'First + 2) := Stream_Element (Shift_Right (Value, 8) and 16#0ff#);
      Buf.Data (Block_Index'First + 3) := Stream_Element (Value and 16#0ff#);
      Into.Pos := Block_Index'First + 3;
   end Set_Header;

   procedure Put_Unsigned_16 (Into  : in out Marshaller;
                              Value : in Interfaces.Unsigned_16) is
      Pos : constant Block_Index := Into.Pos;
      Buf : constant Buffers.Buffer_Accessor := Into.Buffer.Data.Value;
   begin
      Into.Pos := Pos + 2;
      Buf.Data (Pos + 1) := Stream_Element (Shift_Right (Value, 8));
      Buf.Data (Pos + 2) := Stream_Element (Value and 16#0ff#);
   end Put_Unsigned_16;

   procedure Put_Unsigned_32 (Into  : in out Marshaller;
                              Value : in Interfaces.Unsigned_32) is
      Pos : constant Block_Index := Into.Pos;
      Buf : constant Buffers.Buffer_Accessor := Into.Buffer.Data.Value;
   begin
      Into.Pos := Pos + 4;
      Buf.Data (Pos + 1) := Stream_Element (Shift_Right (Value, 24));
      Buf.Data (Pos + 2) := Stream_Element (Shift_Right (Value, 16) and 16#0ff#);
      Buf.Data (Pos + 3) := Stream_Element (Shift_Right (Value, 8) and 16#0ff#);
      Buf.Data (Pos + 4) := Stream_Element (Value and 16#0ff#);
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

         when T_FILE =>
            Put_Unsigned_16 (Into, 4);

         when T_DIRECTORY =>
            Put_Unsigned_16 (Into, 5);

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

   procedure Put_Buffer_Size (Into  : in out Marshaller;
                              Value : in Buffer_Size) is
   begin
      Put_Unsigned_16 (Into, Interfaces.Unsigned_16 (Value));
   end Put_Buffer_Size;

   procedure Put_String (Into  : in out Marshaller;
                         Value : in String) is
      Pos : Block_Index;
      Buf : constant Buffers.Buffer_Accessor := Into.Buffer.Data.Value;
   begin
      Put_Unsigned_16 (Into, Value'Length);
      Pos := Into.Pos;
      Into.Pos := Into.Pos + Value'Length;
      for C of Value loop
         Pos := Pos + 1;
         Buf.Data (Pos) := Character'Pos (C);
      end loop;
   end Put_String;

   procedure Put_Date (Into  : in out Marshaller;
                       Value : in Ada.Calendar.Time) is
      Unix_Time : constant Unsigned_64 :=
        Unsigned_64 (Ada.Calendar.Conversions.To_Unix_Nano_Time (Value));
   begin
      Put_Unsigned_64 (Into, Unix_Time / 1_000_000_000);
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
      Pos        : constant Block_Index := Into.Pos + 1;
      Buf        : constant Buffers.Buffer_Accessor := Into.Buffer.Data.Value;
      IV         : constant Util.Encoders.AES.Word_Block_Type
        := (others => Interfaces.Unsigned_32 (Into.Buffer.Block.Block));
   begin
      Cipher_Key.Set_Key (Protect_Key, Util.Encoders.AES.CBC);
      Cipher_Key.Set_IV (Protect_IV, IV);
      Cipher_Key.Set_Padding (Util.Encoders.AES.NO_PADDING);

      --  Encrypt the key into the key-slot using the protection key.
      Last := Pos + Block_Index (Value.Length) - 1;
      Cipher_Key.Encrypt_Secret (Secret  => Value,
                                 Into    => Buf.Data (Pos .. Last));
      Into.Pos := Last;
   end Put_Secret;

   procedure Put_HMAC_SHA256 (Into    : in out Marshaller;
                              Key     : in Secret_Key;
                              Content : in Ada.Streams.Stream_Element_Array) is
      Pos : constant Block_Index := Into.Pos;
      Buf : constant Buffers.Buffer_Accessor := Into.Buffer.Data.Value;
   begin
      Into.Pos := Into.Pos + SIZE_HMAC;

      --  Make HMAC-SHA256 signature of the data content before encryption.
      Util.Encoders.HMAC.SHA256.Sign (Key    => Key,
                                      Data   => Content,
                                      Result => Buf.Data (Pos + 1 .. Into.Pos));
   end Put_HMAC_SHA256;

   procedure Put_UUID (Into  : in out Marshaller;
                       Value : in UUID_Type) is
   begin
      for I in Value'Range loop
         Put_Unsigned_32 (Into, Value (I));
      end loop;
   end Put_UUID;

   function Get_Header (From  : in out Marshaller) return Interfaces.Unsigned_32 is
      Buf : constant Buffers.Buffer_Accessor := From.Buffer.Data.Value;
   begin
      From.Pos := Block_Index'First + 3;
      return Shift_Left (Unsigned_32 (Buf.Data (Block_Index'First)), 24) or
        Shift_Left (Unsigned_32 (Buf.Data (Block_Index'First + 1)), 16) or
        Shift_Left (Unsigned_32 (Buf.Data (Block_Index'First + 2)), 8) or
        Unsigned_32 (Buf.Data (Block_Index'First + 3));
   end Get_Header;

   function Get_Header_16 (From  : in out Marshaller) return Interfaces.Unsigned_16 is
      Buf : constant Buffers.Buffer_Accessor := From.Buffer.Data.Value;
   begin
      From.Pos := Block_Index'First + 1;
      return Shift_Left (Unsigned_16 (Buf.Data (Block_Index'First)), 8) or
        Unsigned_16 (Buf.Data (Block_Index'First + 1));
   end Get_Header_16;

   function Get_Unsigned_16 (From  : in out Marshaller) return Interfaces.Unsigned_16 is
      Pos : constant Block_Index := From.Pos;
      Buf : constant Buffers.Buffer_Accessor := From.Buffer.Data.Value;
   begin
      From.Pos := Pos + 2;
      return Shift_Left (Unsigned_16 (Buf.Data (Pos + 1)), 8) or
        Unsigned_16 (Buf.Data (Pos + 2));
   end Get_Unsigned_16;

   function Get_Unsigned_32 (From  : in out Marshaller) return Interfaces.Unsigned_32 is
      Pos : constant Block_Index := From.Pos;
      Buf : constant Buffers.Buffer_Accessor := From.Buffer.Data.Value;
   begin
      From.Pos := Pos + 4;
      return Shift_Left (Unsigned_32 (Buf.Data (Pos + 1)), 24) or
        Shift_Left (Unsigned_32 (Buf.Data (Pos + 2)), 16) or
        Shift_Left (Unsigned_32 (Buf.Data (Pos + 3)), 8) or
        Unsigned_32 (Buf.Data (Pos + 4));
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

   procedure Get_String (From   : in out Marshaller;
                         Result : in out String) is
      Pos    : Block_Index := From.Pos;
      Buf    : constant Buffers.Buffer_Accessor := From.Buffer.Data.Value;
   begin
      From.Pos := From.Pos + Block_Index (Result'Length);
      for I in Result'Range loop
         Pos := Pos + 1;
         Result (I) := Character'Val (Buf.Data (Pos));
      end loop;
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

         when 4 =>
            return T_FILE;

         when 5 =>
            return T_DIRECTORY;

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
      Pos           : constant Block_Index := From.Pos + 1;
      Buf           : constant Buffers.Buffer_Accessor := From.Buffer.Data.Value;
      IV            : constant Util.Encoders.AES.Word_Block_Type
        := (others => Interfaces.Unsigned_32 (From.Buffer.Block.Block));
   begin
      Decipher_Key.Set_Key (Protect_Key, Util.Encoders.AES.CBC);
      Decipher_Key.Set_IV (Protect_IV, IV);
      Decipher_Key.Set_Padding (Util.Encoders.AES.NO_PADDING);

      Last := Pos + Block_Index (Secret.Length) - 1;
      Decipher_Key.Decrypt_Secret (Data   => Buf.Data (Pos .. Last),
                                   Secret => Secret);
      From.Pos := Last;
   end Get_Secret;

   procedure Get_UUID (From : in out Marshaller;
                       UUID : out UUID_Type) is
   begin
      for I in UUID'Range loop
         UUID (I) := Marshallers.Get_Unsigned_32 (From);
      end loop;
   end Get_UUID;

   procedure Get_Data (From : in out Marshaller;
                       Size : in Ada.Streams.Stream_Element_Offset;
                       Data : out Ada.Streams.Stream_Element_Array;
                       Last : out Ada.Streams.Stream_Element_Offset) is
      Buf : constant Buffers.Buffer_Accessor := From.Buffer.Data.Value;
      Pos : constant Block_Index := From.Pos + 1;
   begin
      Last := Data'First + Size - 1;
      Data (Data'First .. Last) := Buf.Data (Pos .. Pos + Size - 1);
      From.Pos := Pos + Size - 1;
   end Get_Data;

   procedure Skip (From  : in out Marshaller;
                   Count : in Block_Index) is
   begin
      From.Pos := From.Pos + Count;
   end Skip;

end Keystore.Marshallers;
