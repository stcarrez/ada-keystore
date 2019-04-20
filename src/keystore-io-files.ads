-----------------------------------------------------------------------
--  keystore-io-files -- Ada keystore IO for files
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
with Ada.Direct_IO;
with Ada.Containers.Ordered_Sets;
package Keystore.IO.Files is

   package Block_Number_Sets is
     new Ada.Containers.Ordered_Sets (Element_Type => Block_Number,
                                      "<"          => "<",
                                      "="          => "=");

   package Block_IO is
      new Ada.Direct_IO (Element_Type => Keystore.IO.Block_Type);

   use type Block_IO.Positive_Count;

   subtype Positive_Count is Block_IO.Positive_Count;

   protected type Wallet_File_Stream is new Keystore.IO.Wallet_Stream with

      procedure Open (Path : in String);

      procedure Create (Path : in String);

      --  Read from the wallet stream the block identified by the number and
      --  call the `Process` procedure with the data block content.
      procedure Read (Block   : in Block_Number;
                      Process : not null access
                        procedure (Data : in Block_Type));

      --  Write in the wallet stream the block identified by the block number.
      procedure Write (Block   : in Block_Number;
                       Process : not null access
                         procedure (Data : out Block_Type));

      --  Returns true if the block number is allocated.
      function Is_Used (Block  : in Block_Number) return Boolean;

      --  Allocate a new block and return the block number in `Block`.
      procedure Allocate (Block  : out Block_Number);

      --  Release the block number.
      procedure Release (Block  : in Block_Number);

      --  Close the keystore file.
      procedure Close;

   private
      File        : Block_IO.File_Type;
      Size        : Block_IO.Count;
      Data        : Marshaller;
      Free_Blocks : Block_Number_Sets.Set;
   end Wallet_File_Stream;

   type Wallet_File_Stream_Access is access all Wallet_File_Stream;

end Keystore.IO.Files;
