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
with Ada.Containers.Ordered_Sets;
with Ada.Containers.Hashed_Maps;
with Util.Streams.Raw;
private with Util.Systems.Types;
private with Ada.Finalization;
package Keystore.IO.Files is

   type Wallet_Stream is limited new Keystore.IO.Wallet_Stream with private;
   type Wallet_Stream_Access is access all Wallet_Stream'Class;

   --  Open the wallet stream.
   procedure Open (Stream : in out Wallet_Stream;
                   Path   : in String);

   procedure Create (Stream : in out Wallet_Stream;
                     Path   : in String;
                     Config : in Wallet_Config);

   --  Read from the wallet stream the block identified by the number and
   --  call the `Process` procedure with the data block content.
   overriding
   procedure Read (Stream  : in out Wallet_Stream;
                   Block   : in Storage_Block;
                   Process : not null access
                     procedure (Data : in Block_Type));

   --  Write in the wallet stream the block identified by the block number.
   overriding
   procedure Write (Stream  : in out Wallet_Stream;
                    Block   : in Storage_Block;
                    Process : not null access
                      procedure (Data : out Block_Type));

   --  Allocate a new block and return the block number in `Block`.
   overriding
   procedure Allocate (Stream  : in out Wallet_Stream;
                       Kind    : in Block_Kind;
                       Block   : out Storage_Block);

   --  Release the block number.
   overriding
   procedure Release (Stream  : in out Wallet_Stream;
                      Block   : in Storage_Block);

   overriding
   function Is_Used (Stream  : in out Wallet_Stream;
                     Block   : in Storage_Block) return Boolean;

   --  Close the wallet stream and release any resource.
   procedure Close (Stream : in out Wallet_Stream);

private

   use type Block_Number;
   use type Storage_Identifier;

   package Block_Number_Sets is
     new Ada.Containers.Ordered_Sets (Element_Type => Block_Number,
                                      "<"          => "<",
                                      "="          => "=");

   protected type File_Stream is

      procedure Open (File_Descriptor : in Util.Systems.Types.File_Type;
                      File_Size       : in Block_Count);

      --  Read from the wallet stream the block identified by the number and
      --  call the `Process` procedure with the data block content.
      procedure Read (Block   : in Block_Number;
                      Process : not null access
                        procedure (Data : in Block_Type));

      --  Write in the wallet stream the block identified by the block number.
      procedure Write (Block   : in Block_Number;
                       Process : not null access
                         procedure (Data : out Block_Type));

      --  Allocate a new block and return the block number in `Block`.
      procedure Allocate (Block   : out Block_Number);

      --  Release the block number.
      procedure Release (Block   : in Block_Number);

      function Is_Used (Block : in Block_Number) return Boolean;

      procedure Close;

   private
      File        : Util.Streams.Raw.Raw_Stream;
      Current_Pos : Util.Systems.Types.off_t;
      Size        : Block_Count;
      Data        : Block_Type;
      Free_Blocks : Block_Number_Sets.Set;
   end File_Stream;

   type File_Stream_Access is access all File_Stream;

   function Hash (Value : Storage_Identifier) return Ada.Containers.Hash_Type;

   package File_Stream_Maps is
     new Ada.Containers.Hashed_Maps (Key_Type        => Storage_Identifier,
                                     Element_Type    => File_Stream_Access,
                                     Hash            => Hash,
                                     Equivalent_Keys => "=",
                                     "="             => "=");

   protected type Stream_Descriptor is

      procedure Open (Path : in String);

      procedure Create (Path   : in String;
                        Config : in Wallet_Config);

      procedure Get (Storage : in Storage_Identifier;
                     File    : out File_Stream_Access);

      procedure Allocate (Kind    : in Block_Kind;
                          Storage : out Storage_Identifier;
                          File    : out File_Stream_Access);

      procedure Close;

   private
      UUID  : UUID_Type;
      Files : File_Stream_Maps.Map;
   end Stream_Descriptor;

   type Wallet_Stream is limited new Ada.Finalization.Limited_Controlled
     and Keystore.IO.Wallet_Stream with record
      Descriptor : Stream_Descriptor;
   end record;

end Keystore.IO.Files;
