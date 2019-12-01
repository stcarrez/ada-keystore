-----------------------------------------------------------------------
--  keystore-io-tests -- Tests for keystore IO
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

with Util.Test_Caller;
with Util.Measures;
with Util.Encoders.AES;
with Keystore.IO.Files;
with Keystore.Buffers;
with Keystore.Marshallers;
package body Keystore.IO.Tests is

   use type Keystore.Buffers.Block_Number;

   package Caller is new Util.Test_Caller (Test, "Keystore.IO");

   procedure Add_Tests (Suite : in Util.Tests.Access_Test_Suite) is
   begin
      Caller.Add_Test (Suite, "Test Keystore.IO.Files.Create+Open+Write+Read",
                       Test_File_IO'Access);
      Caller.Add_Test (Suite, "Test Keystore.IO.Files.Perf",
                       Test_Perf_IO'Access);
   end Add_Tests;

   procedure Test_File_IO (T : in out Test) is
      Path     : constant String := Util.Tests.Get_Test_Path ("regtests/result/test-io.ks");
      Secret   : Secret_Key := Util.Encoders.Create ("0123456789abcdef");
      Secret2  : Secret_Key := Util.Encoders.Create ("0123456789abcdef0123456789abcdef");
      Block    : Storage_Block;
      Sign     : constant Secret_Key := Util.Encoders.Create ("0123456789abcdef0123456789abcdef");
   begin
      --  Make a file with a zero-ed block.
      declare
         Stream   : Keystore.IO.Files.Wallet_Stream;
         Buffer   : Keystore.IO.Marshaller;
         Cipher   : Util.Encoders.AES.Encoder;
         Config   : Keystore.Wallet_Config := Keystore.Unsecure_Config;
      begin
         Config.Overwrite := True;
         Cipher.Set_Key (Secret);
         Cipher.Set_Padding (Util.Encoders.AES.NO_PADDING);
         Stream.Create (Path => Path, Data_Path => "", Config => Config);
         Stream.Allocate (IO.DATA_BLOCK, Block);
         T.Assert (Block.Block = 1, "Allocate should return first block");

         Buffer.Buffer := Buffers.Allocate (Block);
         Buffer.Buffer.Data.Value.Data := (others => 0);
         Marshallers.Set_Header (Buffer, Tag => BT_WALLET_HEADER, Id => 12);
         Marshallers.Put_Unsigned_32 (Buffer, 12345);
         Stream.Write (Cipher => Cipher,
                       Sign   => Sign,
                       From   => Buffer.Buffer);
         Stream.Close;
      end;

      --  Read same file and verify we can extract correctly the block data.
      declare
         Stream   : Keystore.IO.Files.Wallet_Stream;
         Buffer   : Keystore.IO.Marshaller;
         Decipher : Util.Encoders.AES.Decoder;
         Size     : Block_Index;
      begin
         Decipher.Set_Key (Secret);
         Decipher.Set_Padding (Util.Encoders.AES.NO_PADDING);
         Stream.Open (Path => Path, Data_Path => "");
         Buffer.Buffer := Buffers.Allocate (Storage_Block '(DEFAULT_STORAGE_ID, 1));
         Stream.Read (Decipher     => Decipher,
                      Sign         => Sign,
                      Decrypt_Size => Size,
                      Into         => Buffer.Buffer);
         Util.Tests.Assert_Equals (T, BT_WALLET_HEADER,
                                   Integer (Marshallers.Get_Header_16 (Buffer)),
                                   "Invalid wallet header tag");
         Util.Tests.Assert_Equals (T, Natural (Size),
                                   Integer (Marshallers.Get_Unsigned_16 (Buffer)),
                                   "Invalid wallet encryption size");
         Util.Tests.Assert_Equals (T, 12,
                                   Integer (Marshallers.Get_Unsigned_32 (Buffer)),
                                   "Invalid wallet id");
         Util.Tests.Assert_Equals (T, 0,
                                   Integer (Marshallers.Get_Unsigned_32 (Buffer)),
                                   "Invalid PAD 0");
         Util.Tests.Assert_Equals (T, 0,
                                   Integer (Marshallers.Get_Unsigned_32 (Buffer)),
                                   "Invalid PAD 0");
         Util.Tests.Assert_Equals (T, 12345,
                                   Integer (Marshallers.Get_Unsigned_32 (Buffer)),
                                   "Invalid number extracted from block");
         Stream.Close;
      end;

      --  Use a wrong decompression key and verify we get an error.
      declare
         Stream   : Keystore.IO.Files.Wallet_Stream;
         Buffer   : Keystore.IO.Marshaller;
         Decipher : Util.Encoders.AES.Decoder;
         Size     : Block_Index;
      begin
         Decipher.Set_Key (Secret2);
         Decipher.Set_Padding (Util.Encoders.AES.NO_PADDING);
         Stream.Open (Path => Path, Data_Path => "");
         begin
            Buffer.Buffer := Buffers.Allocate (Storage_Block '(DEFAULT_STORAGE_ID, 1));
            Stream.Read (Decipher     => Decipher,
                         Sign         => Sign,
                         Decrypt_Size => Size,
                         Into         => Buffer.Buffer);
            T.Fail ("An Invalid_Block exception is expected.");

         exception
            when Invalid_Block | Invalid_Signature =>
               null;
         end;
         Stream.Close;
      end;
   end Test_File_IO;

   procedure Test_Perf_IO (T : in out Test) is
      Path     : constant String := Util.Tests.Get_Test_Path ("regtests/result/test-io-perf.ks");
      Secret   : Secret_Key := Util.Encoders.Create ("0123456789abcdef");
      Block    : Storage_Block;
      Sign     : constant Secret_Key := Util.Encoders.Create ("123456789abcdef0");
   begin
      --  Make a file with filled blocks.
      declare
         Start    : Util.Measures.Stamp;
         Stream   : Keystore.IO.Files.Wallet_Stream;
         Buffer   : Keystore.IO.Marshaller;
         Cipher   : Util.Encoders.AES.Encoder;
         Config   : Keystore.Wallet_Config := Keystore.Unsecure_Config;
      begin
         Config.Overwrite := True;
         Cipher.Set_Key (Secret);
         Cipher.Set_Padding (Util.Encoders.AES.NO_PADDING);
         Stream.Create (Path => Path, Data_Path => "", Config => Config);
         Stream.Allocate (IO.DATA_BLOCK, Block);
         T.Assert (Block.Block = 1, "Allocate should return first block");

         Buffer.Buffer := Buffers.Allocate (Block);
         Buffer.Buffer.Data.Value.Data := (others => 0);
         Marshallers.Set_Header (Buffer, Tag => BT_WALLET_HEADER, Id => 12);
         Marshallers.Put_Unsigned_32 (Buffer, 12345);
         Stream.Write (Cipher => Cipher,
                       Sign   => Sign,
                       From   => Buffer.Buffer);

         for I in 1 .. 1000 loop
            Stream.Allocate (IO.DATA_BLOCK, Block);
            Buffer.Buffer := Buffers.Allocate (Block);
            Buffer.Buffer.Data.Value.Data := (others => Stream_Element (I mod 255));
            Marshallers.Set_Header (Buffer, Tag => BT_WALLET_DATA, Id => 12);
            Stream.Write (Cipher => Cipher,
                          Sign   => Sign,
                          From   => Buffer.Buffer);
         end loop;
         Stream.Close;
         Util.Measures.Report (Start, "Write 1000 blocks");
      end;

      --  Read same file and verify we can extract correctly the block data.
      declare
         Start    : Util.Measures.Stamp;
         Stream   : Keystore.IO.Files.Wallet_Stream;
         Buffer   : Keystore.IO.Marshaller;
         Decipher : Util.Encoders.AES.Decoder;
         Size     : Block_Index;
      begin
         Decipher.Set_Key (Secret);
         Decipher.Set_Padding (Util.Encoders.AES.NO_PADDING);
         Stream.Open (Path => Path, Data_Path => "");
         Buffer.Buffer := Buffers.Allocate (Storage_Block '(DEFAULT_STORAGE_ID, 1));

         --  Read first block
         Stream.Read (Decipher     => Decipher,
                      Sign         => Sign,
                      Decrypt_Size => Size,
                      Into         => Buffer.Buffer);

         Util.Tests.Assert_Equals (T, BT_WALLET_HEADER,
                                   Integer (Marshallers.Get_Header_16 (Buffer)),
                                   "Invalid wallet header tag");
         Util.Tests.Assert_Equals (T, Natural (Size),
                                   Integer (Marshallers.Get_Unsigned_16 (Buffer)),
                                   "Invalid wallet encryption size");
         Util.Tests.Assert_Equals (T, 12,
                                   Integer (Marshallers.Get_Unsigned_32 (Buffer)),
                                   "Invalid wallet id");
         Util.Tests.Assert_Equals (T, 0,
                                   Integer (Marshallers.Get_Unsigned_32 (Buffer)),
                                   "Invalid PAD 0");
         Util.Tests.Assert_Equals (T, 0,
                                   Integer (Marshallers.Get_Unsigned_32 (Buffer)),
                                   "Invalid PAD 0");
         Util.Tests.Assert_Equals (T, 12345,
                                   Integer (Marshallers.Get_Unsigned_32 (Buffer)),
                                   "Invalid number extracted from block");

         --  Read other blocks
         for I in 1 .. 1000 loop
            Buffer.Buffer := Buffers.Allocate (Storage_Block '(DEFAULT_STORAGE_ID,
                                               IO.Block_Number (I + 1)));
            Stream.Read (Decipher     => Decipher,
                         Sign         => Sign,
                         Decrypt_Size => Size,
                         Into         => Buffer.Buffer);

            Util.Tests.Assert_Equals (T, BT_WALLET_DATA,
                                      Integer (Marshallers.Get_Header_16 (Buffer)),
                                      "Invalid wallet header tag");
            Util.Tests.Assert_Equals (T, Natural (Size),
                                      Integer (Marshallers.Get_Unsigned_16 (Buffer)),
                                      "Invalid wallet encryption size");
            Util.Tests.Assert_Equals (T, 12,
                                      Integer (Marshallers.Get_Unsigned_32 (Buffer)),
                                      "Invalid wallet id");
            Util.Tests.Assert_Equals (T, 0,
                                      Integer (Marshallers.Get_Unsigned_32 (Buffer)),
                                      "Invalid PAD 0");
            Util.Tests.Assert_Equals (T, 0,
                                      Integer (Marshallers.Get_Unsigned_32 (Buffer)),
                                      "Invalid PAD 0");
            Util.Tests.Assert_Equals (T, I mod 255,
                                      Integer (Buffer.Buffer.Data.Value.Data (Buffer.Pos + 1)),
                                      "Invalid number extracted from block");
            Util.Tests.Assert_Equals (T, I mod 255,
                                      Integer (Buffer.Buffer.Data.Value.Data (Buffer.Pos + 123)),
                                      "Invalid number extracted from block");
         end loop;
         Stream.Close;
         Util.Measures.Report (Start, "Read 1000 blocks");
      end;

   end Test_Perf_IO;

end Keystore.IO.Tests;
