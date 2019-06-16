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
with Ada.Streams;
with Ada.Finalization;
with Ada.Strings.Unbounded;
with Interfaces;
with Util.Encoders.AES;
private with Ada.Numerics.Discrete_Random;

--  == Random Generator ==
--  The <tt>Security.Random</tt> package defines the <tt>Generator</tt> tagged type
--  which provides operations to generate random tokens intended to be used for
--  a nonce, access token, salt or other purposes.  The generator is intended to be
--  used in multi-task environments as it implements the low level random generation
--  within a protected type.  The generator defines a <tt>Generate</tt> operation
--  that returns either a binary random array or the base64url encoding of the
--  binary array.
package Keystore.Random is

   type Generator is limited new Ada.Finalization.Limited_Controlled with private;

   --  Initialize the random generator.
   overriding
   procedure Initialize (Gen : in out Generator);

   --  Fill the array with pseudo-random numbers.
   procedure Generate (Gen  : in out Generator;
                       Into : out Ada.Streams.Stream_Element_Array);

   --  Fill the array with pseudo-random numbers.
   procedure Generate (Gen  : in out Generator;
                       Into : out Util.Encoders.AES.Word_Block_Type);

   procedure Generate (Gen  : in out Generator;
                       Into : out Secret_Key);

   --  Generate a random sequence of bits and convert the result
   --  into a string in base64url.
   function Generate (Gen  : in out Generator'Class;
                      Bits : in Positive) return String;

   function Generate (Gen : in out Generator'Class) return Interfaces.Unsigned_32;

   --  Generate a random sequence of bits, convert the result
   --  into a string in base64url and append it to the buffer.
   procedure Generate (Gen  : in out Generator'Class;
                       Bits : in Positive;
                       Into : in out Ada.Strings.Unbounded.Unbounded_String);

private

   package Id_Random is new Ada.Numerics.Discrete_Random (Interfaces.Unsigned_32);

   --  Protected type to allow using the random generator by several tasks.
   protected type Raw_Generator is

      procedure Generate (Into : out Ada.Streams.Stream_Element_Array);

      procedure Generate (Value : out Interfaces.Unsigned_32);

      procedure Reset;
   private
      --  Random number generator used for ID generation.
      Rand  : Id_Random.Generator;
   end Raw_Generator;

   type Generator is limited new Ada.Finalization.Limited_Controlled with record
      Rand : Raw_Generator;
   end record;

end Keystore.Random;
