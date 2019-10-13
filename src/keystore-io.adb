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
with Util.Log.Loggers;
with Util.Encoders.SHA256;
with Util.Encoders.HMAC.SHA256;
with Keystore.Logs;

--  Generic Block header
--  +------------------+
--  | Block HMAC-256   | 32b
--  +------------------+
--  | Block type       | 2b
--  | Encrypt 1 size   | 2b
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
package body Keystore.IO is

   use Interfaces;

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Keystore.IO");

   procedure Put_Encrypt_Size (Into  : in out Block_Type;
                               Value : in Block_Index);

   function Get_Decrypt_Size (From : in Block_Type) return Interfaces.Unsigned_16;

   procedure Put_Encrypt_Size (Into  : in out Block_Type;
                               Value : in Block_Index) is
      V : constant Interfaces.Unsigned_16 := Interfaces.Unsigned_16 (Value);
   begin
      Into (BT_HEADER_START + 2) := Stream_Element (Shift_Right (V, 8));
      Into (BT_HEADER_START + 3) := Stream_Element (V and 16#0ff#);
   end Put_Encrypt_Size;

   function Get_Decrypt_Size (From : in Block_Type) return Interfaces.Unsigned_16 is
   begin
      return Shift_Left (Unsigned_16 (From (BT_HEADER_START + 2)), 8) or
        Unsigned_16 (From (BT_HEADER_START + 3));
   end Get_Decrypt_Size;

   --  ------------------------------
   --  Read the block from the wallet IO stream and decrypt the block content using
   --  the decipher object.  The decrypted content is stored in the marshaller which
   --  is ready to read the start of the block header.
   --  ------------------------------
   procedure Read (Stream       : in out Wallet_Stream'Class;
                   Decipher     : in out Util.Encoders.AES.Decoder;
                   Sign         : in Secret_Key;
                   Decrypt_Size : out Block_Index;
                   Into         : in out Buffers.Storage_Buffer) is

      procedure Read (Data : in Block_Type);

      procedure Read (Data : in Block_Type) is
         Last      : Stream_Element_Offset;
         Encoded   : Stream_Element_Offset;
         Hash      : Util.Encoders.SHA256.Hash_Array;
         Last_Pos  : Stream_Element_Offset;
         Context   : Util.Encoders.HMAC.SHA256.Context;
         Size      : Interfaces.Unsigned_16;
         Buf       : constant Buffers.Buffer_Accessor := Into.Data.Value;
      begin
         Size := Get_Decrypt_Size (Data);

         --  Check that the decrypt size looks correct.
         if Size = 0 or else Size > Data'Length or else (Size mod 16) /= 0 then
            Keystore.Logs.Warn (Log, "Bloc{0} has invalid size", Into.Block);
            raise Invalid_Block;
         end if;
         Decrypt_Size := Block_Index (Size);

         Last_Pos := BT_DATA_START + Stream_Element_Offset (Decrypt_Size) - 1;

         Buf.Data (Buf.Data'First .. BT_DATA_START - 1)
           := Data (Data'First .. BT_DATA_START - 1);

         if Log.Get_Level >= Util.Log.INFO_LEVEL then
            Log.Info ("Read block{0} decrypt {1} .. {2}",
                      Buffers.To_String (Into.Block),
                      Stream_Element_Offset'Image (BT_DATA_START),
                      Stream_Element_Offset'Image (Last_Pos));
         end if;

         --  Decrypt the Size bytes
         Decipher.Transform (Data    => Data (BT_DATA_START .. Last_Pos),
                             Into    => Buf.Data (BT_DATA_START .. Last_Pos),
                             Last    => Last,
                             Encoded => Encoded);
         Decipher.Finish (Into => Buf.Data (Last + 1 .. Last_Pos),
                          Last => Last);
         if Encoded - 1 /= Last_Pos or Last /= Last_Pos then
            Keystore.Logs.Warn (Log, "Bloc{0} decryption failed", Into.Block);
            raise Invalid_Block;
         end if;
         if Last_Pos < Buf.Data'Last then
            Buf.Data (Last_Pos + 1 .. Buf.Data'Last) := Data (Last_Pos + 1 .. Data'Last);
         end if;

         Keystore.Logs.Debug (Log, "Dump block{0} before AES decrypt", Into.Block);
         Keystore.Logs.Dump (Log, Data (BT_DATA_START .. BT_DATA_START + 95));
         --  Keystore.Logs.Debug (Log, "...", 1);
         Keystore.Logs.Dump (Log, Data (Buf.Data'Last - 100 .. Buf.Data'Last));

         Keystore.Logs.Debug (Log, "Dump block{0} after AES decrypt", Into.Block);
         Keystore.Logs.Dump (Log, Buf.Data (BT_DATA_START .. BT_DATA_START + 95));
         --  Keystore.Logs.Debug (Log, "...", 1);
         Keystore.Logs.Dump (Log, Buf.Data (Buf.Data'Last - 100 .. Buf.Data'Last));

         --  Make HMAC-SHA256 signature of the block excluding the block hash mac.
         Util.Encoders.HMAC.SHA256.Set_Key (Context, Sign);
         Util.Encoders.HMAC.SHA256.Update (Context, Buf.Data (BT_HEADER_START .. Last_Pos));
         if Last_Pos /= Buf.Data'Last then
            Util.Encoders.HMAC.SHA256.Update (Context, Buf.Data (Last_Pos + 1 .. Buf.Data'Last));
         end if;
         Util.Encoders.HMAC.SHA256.Finish (Context, Hash);

         --  Check that the block hash mac matches our hash.
         if Hash /= Buf.Data (Buf.Data'First .. BT_HMAC_HEADER_SIZE) then
            Keystore.Logs.Warn (Log, "Block{0} HMAC-256 is invalid", Into.Block);
            raise Invalid_Block;
         end if;
         --  Into.Pos := BT_HEADER_START;
      end Read;

   begin
      Stream.Read (Into.Block, Read'Access);
   end Read;

   --  ------------------------------
   --  Write the block in the wallet IO stream.  Encrypt the block data using the
   --  cipher object.  Sign the header and encrypted data using HMAC-256 and the
   --  given signature.
   --  ------------------------------
   procedure Write (Stream       : in out Wallet_Stream'Class;
                    Encrypt_Size : in Block_Index := BT_DATA_LENGTH;
                    Cipher       : in out Util.Encoders.AES.Encoder;
                    Sign         : in Secret_Key;
                    From         : in out Buffers.Storage_Buffer) is

      procedure Write (Data : out Block_Type);

      procedure Write (Data : out Block_Type) is
         Last     : Stream_Element_Offset;
         Encoded  : Stream_Element_Offset;
         Last_Pos : constant Stream_Element_Offset := BT_DATA_START + Encrypt_Size - 1;
         Buf      : constant Buffers.Buffer_Accessor := From.Data.Value;
      begin
         if Log.Get_Level >= Util.Log.INFO_LEVEL then
            Log.Info ("Write block{0} encrypt {1} .. {2}",
                      Buffers.To_String (From.Block),
                      Stream_Element_Offset'Image (BT_DATA_START),
                      Stream_Element_Offset'Image (Last_Pos));
         end if;

         Put_Encrypt_Size (Buf.Data, Encrypt_Size);

         Data (BT_HEADER_START .. BT_DATA_START - 1)
           := Buf.Data (BT_HEADER_START .. BT_DATA_START - 1);
         Cipher.Transform (Data    => Buf.Data (BT_DATA_START .. Last_Pos),
                           Into    => Data (BT_DATA_START .. Last_Pos),
                           Last    => Last,
                           Encoded => Encoded);
         Log.Info ("Last={0} Encoded={0}",
                   Stream_Element_Offset'Image (Last),
                   Stream_Element_Offset'Image (Encoded));
         if Last_Pos < Data'Last then
            Data (Last_Pos + 1 .. Data'Last) := Buf.Data (Last_Pos + 1 .. Data'Last);
         end if;

         Keystore.Logs.Debug (Log, "Dump data block{0} before AES and write", From.Block);
         Keystore.Logs.Dump (Log, Buf.Data (BT_DATA_START .. BT_DATA_START + 95));
         --  Keystore.Logs.Debug (Log, "...", 1);
         Keystore.Logs.Dump (Log, Buf.Data (Buf.Data'Last - 100 .. Buf.Data'Last));

         Keystore.Logs.Debug (Log, "Dump data block{0} after AES and write", From.Block);
         Keystore.Logs.Dump (Log, Data (BT_DATA_START .. BT_DATA_START + 95));
         --  Keystore.Logs.Debug (Log, "...", 1);
         Keystore.Logs.Dump (Log, Data (Buf.Data'Last - 100 .. Buf.Data'Last));

         --  Make HMAC-SHA256 signature of the block excluding the block hash mac.
         Util.Encoders.HMAC.SHA256.Sign (Key    => Sign,
                                         Data   => Buf.Data (BT_HEADER_START .. Data'Last),
                                         Result => Data (Data'First .. BT_HMAC_HEADER_SIZE));
      end Write;

   begin
      Stream.Write (From.Block, Write'Access);
   end Write;

end Keystore.IO;
