-----------------------------------------------------------------------
--  keystore-buffers -- Buffer management for the keystore
--  Copyright (C) 2019, 2020 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

package body Keystore.Buffers is

   --  ------------------------------
   --  Get a printable representation of storage block for the logs.
   --  ------------------------------
   function To_String (Value : in Storage_Block) return String is
      Sid : constant String := Storage_Identifier'Image (Value.Storage);
      Bid : constant String := Block_Number'Image (Value.Block);
   begin
      return Sid (Sid'First + 1 .. Sid'Last) & "." & Bid (Bid'First + 1 .. Bid'Last);
   end To_String;

   --  ------------------------------
   --  Find a buffer from the container.
   --  ------------------------------
   function Find (Container : in Buffer_Map;
                  Block     : in Storage_Block) return Storage_Buffer is
      Buffer : Storage_Buffer;
      Pos    : Buffer_Cursor;
   begin
      Buffer.Block := Block;
      Pos := Container.Find (Block);
      if Buffer_Maps.Has_Element (Pos) then
         Buffer.Data := Buffer_Maps.Element (Pos);
      end if;
      return Buffer;
   end Find;

   --  ------------------------------
   --  Allocate a buffer for the storage block.
   --  ------------------------------
   function Allocate (Block : in Storage_Block) return Storage_Buffer is
      Buffer : Storage_Buffer;
   begin
      Buffer.Block := Block;
      Buffer.Data := Buffer_Refs.Create;
      return Buffer;
   end Allocate;

end Keystore.Buffers;
