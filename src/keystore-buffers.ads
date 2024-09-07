-----------------------------------------------------------------------
--  keystore-buffers -- Buffer management for the keystore
--  Copyright (C) 2019, 2020 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with Ada.Streams;
with Ada.Containers.Ordered_Maps;
with Util.Refs;
with Util.Strings;
private package Keystore.Buffers is

   use Ada.Streams;

   BT_HMAC_HEADER_SIZE  : constant := 32;

   --  Data block size defined to a 4K to map system page.
   Block_Size           : constant := 4096;

   BT_DATA_SIZE         : constant := Block_Size - BT_HMAC_HEADER_SIZE;

   subtype Buffer_Size is Stream_Element_Offset range 0 .. BT_DATA_SIZE;

   subtype Block_Index is Stream_Element_Offset range 1 .. BT_DATA_SIZE;

   subtype IO_Block_Type is Stream_Element_Array (1 .. Block_Size);

   subtype Block_Type is Stream_Element_Array (Block_Index);

   function Image (Value : Block_Index) return String is
      (Util.Strings.Image (Natural (Value)));

   type Block_Count is new Interfaces.Unsigned_32;

   subtype Block_Number is Block_Count range 1 .. Block_Count'Last;

   type Storage_Identifier is new Interfaces.Unsigned_32;

   type Storage_Block is record
      Storage : Storage_Identifier := 0;
      Block   : Block_Number := Block_Number'First;
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

   --  Find a buffer from the container.
   function Find (Container : in Buffer_Map;
                  Block     : in Storage_Block) return Storage_Buffer;

   --  Allocate a buffer for the storage block.
   function Allocate (Block : in Storage_Block) return Storage_Buffer;

end Keystore.Buffers;
