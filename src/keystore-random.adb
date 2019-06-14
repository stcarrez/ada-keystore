-----------------------------------------------------------------------
--  security-random -- Random numbers for nonce, secret keys, token generation
--  Copyright (C) 2017 Stephane Carrez
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
with Ada.Calendar;
with Ada.Calendar.Conversions;
with Util.Encoders.Base64;

package body Keystore.Random is

   use Interfaces;

   --  ------------------------------
   --  Initialize the random generator.
   --  ------------------------------
   overriding
   procedure Initialize (Gen : in out Generator) is
   begin
      Gen.Rand.Reset;
   end Initialize;

   --  ------------------------------
   --  Fill the array with pseudo-random numbers.
   --  ------------------------------
   procedure Generate (Gen  : in out Generator;
                       Into : out Ada.Streams.Stream_Element_Array) is
   begin
      Gen.Rand.Generate (Into);
   end Generate;

   --  ------------------------------
   --  Fill the array with pseudo-random numbers.
   --  ------------------------------
   procedure Generate (Gen  : in out Generator;
                       Into : out Util.Encoders.AES.Word_Block_Type) is
      Block : Ada.Streams.Stream_Element_Array (1 .. 16);
      for Block'Address use Into'Address;
   begin
      Gen.Rand.Generate (Block);
   end Generate;

   procedure Generate (Gen  : in out Generator;
                       Into : out Secret_Key) is
      Block : Ada.Streams.Stream_Element_Array (1 .. Into.Length);
   begin
      Gen.Rand.Generate (Block);
      Util.Encoders.Create (Block, Into);
   end Generate;

   --  ------------------------------
   --  Generate a random sequence of bits and convert the result
   --  into a string in base64url.
   --  ------------------------------
   function Generate (Gen  : in out Generator'Class;
                      Bits : in Positive) return String is
      use type Ada.Streams.Stream_Element_Offset;

      Rand_Count : constant Ada.Streams.Stream_Element_Offset
        := Ada.Streams.Stream_Element_Offset (4 * ((Bits + 31) / 32));

      Rand    : Ada.Streams.Stream_Element_Array (0 .. Rand_Count - 1);
      Buffer  : Ada.Streams.Stream_Element_Array (0 .. Rand_Count * 3);
      Encoder : Util.Encoders.Base64.Encoder;
      Last    : Ada.Streams.Stream_Element_Offset;
      Encoded : Ada.Streams.Stream_Element_Offset;
   begin
      --  Generate the random sequence.
      Gen.Generate (Rand);

      --  Encode the random stream in base64url and save it into the result string.
      Encoder.Set_URL_Mode (True);
      Encoder.Transform (Data => Rand, Into => Buffer,
                         Last => Last, Encoded => Encoded);
      declare
         Result : String (1 .. Natural (Encoded + 1));
      begin
         for I in 0 .. Encoded loop
            Result (Natural (I + 1)) := Character'Val (Buffer (I));
         end loop;
         return Result;
      end;
   end Generate;

   --  ------------------------------
   --  Generate a random sequence of bits, convert the result
   --  into a string in base64url and append it to the buffer.
   --  ------------------------------
   procedure Generate (Gen  : in out Generator'Class;
                       Bits : in Positive;
                       Into : in out Ada.Strings.Unbounded.Unbounded_String) is
      use type Ada.Streams.Stream_Element_Offset;

      Rand_Count : constant Ada.Streams.Stream_Element_Offset
        := Ada.Streams.Stream_Element_Offset (4 * ((Bits + 31) / 32));

      Rand    : Ada.Streams.Stream_Element_Array (0 .. Rand_Count - 1);
      Buffer  : Ada.Streams.Stream_Element_Array (0 .. Rand_Count * 3);
      Encoder : Util.Encoders.Base64.Encoder;
      Last    : Ada.Streams.Stream_Element_Offset;
      Encoded : Ada.Streams.Stream_Element_Offset;
   begin
      --  Generate the random sequence.
      Gen.Generate (Rand);

      --  Encode the random stream in base64url and save it into the result string.
      Encoder.Set_URL_Mode (True);
      Encoder.Transform (Data => Rand, Into => Buffer,
                         Last => Last, Encoded => Encoded);
      for I in 0 .. Encoded loop
         Ada.Strings.Unbounded.Append (Into, Character'Val (Buffer (I)));
      end loop;
   end Generate;

   --  Protected type to allow using the random generator by several tasks.
   protected body Raw_Generator is

      procedure Generate (Into : out Ada.Streams.Stream_Element_Array) is
         use Ada.Streams;

         Size   : constant Ada.Streams.Stream_Element_Offset := Into'Length / 4;
         Remain : constant Ada.Streams.Stream_Element_Offset := Into'Length mod 4;
         Value  : Unsigned_32;
      begin
         --  Generate the random sequence (fill 32-bits at a time for each random call).
         for I in 0 .. Size - 1 loop
            Value := Id_Random.Random (Rand);
            Into (Into'First + 4 * I)     := Stream_Element (Value and 16#0FF#);
            Into (Into'First + 4 * I + 1) := Stream_Element (Shift_Right (Value, 8) and 16#0FF#);
            Into (Into'First + 4 * I + 2) := Stream_Element (Shift_Right (Value, 16) and 16#0FF#);
            Into (Into'First + 4 * I + 3) := Stream_Element (Shift_Right (Value, 24) and 16#0FF#);
         end loop;

         --  Fill the remaining bytes.
         if Remain > 0 then
            Value := Id_Random.Random (Rand);
            for I in 0 .. Remain - 1 loop
               Into (Into'Last - I) := Stream_Element (Value and 16#0FF#);
               Value := Shift_Right (Value, 8);
            end loop;
         end if;
      end Generate;

      procedure Reset is
         Now  : constant Ada.Calendar.Time := Ada.Calendar.Clock;
         S    : constant Ada.Calendar.Day_Duration := Ada.Calendar.Seconds (Now);
         Sec  : Interfaces.C.long;
         Nsec : Interfaces.C.long;
      begin
         Ada.Calendar.Conversions.To_Struct_Timespec (S, Sec, Nsec);
         Id_Random.Reset (Rand, Integer (Unsigned_32 (Sec) xor Unsigned_32 (Nsec)));
      end Reset;

   end Raw_Generator;

end Keystore.Random;
