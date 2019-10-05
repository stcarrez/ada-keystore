-----------------------------------------------------------------------
--  keystore-buffers -- Buffer management for the keystore
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
with Ada.Streams;
with Ada.Containers.Ordered_Maps;
with Util.Encoders.AES;
with Util.Refs;
private package Keystore.Buffers is

   use Ada.Streams;

   --  Data block size defined to a 4K to map system page.
   Block_Size           : constant := 4096;

   subtype Buffer_Size is Stream_Element_Offset range 0 .. Block_Size;

   subtype Block_Index is Stream_Element_Offset range 1 .. Block_Size;

   subtype Block_Type is Stream_Element_Array (Block_Index);

   type Block_Count is new Interfaces.Unsigned_32;

   subtype Block_Number is Block_Count range 1 .. Block_Count'Last;

   type Storage_Identifier is new Interfaces.Unsigned_32;

   type Storage_Block is record
      Storage : Storage_Identifier;
      Block   : Block_Number;
   end record;

   --  Get a printable representation of storage block for the logs.
   function To_String (Value : in Storage_Block) return String;

   --  Order the two values on the storage and block number.
   function "<" (Left, Right : in Storage_Block) return Boolean is
     (Left.Storage < Right.Storage or else
      (Left.Storage = Right.Storage and then Left.Block < Right.Block));

   type Data_Buffer_Type is limited record
      Data    : Block_Type;
   end record;

   package Buffer_Refs is new Util.Refs.General_References (Data_Buffer_Type);

   subtype Buffer_Type is Buffer_Refs.Ref;
   subtype Buffer_Accessor is Buffer_Refs.Element_Accessor;

   type Storage_Buffer is record
      Block   : Storage_Block;
      Data    : Buffer_Type;
   end record;

   function Is_Null (Buffer : in Storage_Buffer) return Boolean is (Buffer.Data.Is_Null);

   --  Order the two buffers on the storage and block number.
   function "<" (Left, Right : in Storage_Buffer) return Boolean is (Left.Block < Right.Block);

   --  A set of buffers ordered by storage and block number.
   package Buffer_Maps is
     new Ada.Containers.Ordered_Maps (Key_Type     => Storage_Block,
                                      Element_Type => Buffer_Type,
                                      "<"          => "<",
                                      "="          => Buffer_Refs."=");

   subtype Buffer_Map is Buffer_Maps.Map;
   subtype Buffer_Cursor is Buffer_Maps.Cursor;

   --  Find a buffer from the set of allocate an instance to hold it.
   function Find_Or_Allocate (Container : in Buffer_Map;
                              Storage   : in Storage_Identifier;
                              Block     : in Block_Number) return Storage_Buffer;

   --  Find a buffer from the container.
   function Find (Container : in Buffer_Map;
                  Block     : in Storage_Block) return Storage_Buffer;

   --  Allocate a buffer for the storage block.
   function Allocate (Block : in Storage_Block) return Storage_Buffer;

end Keystore.Buffers;
