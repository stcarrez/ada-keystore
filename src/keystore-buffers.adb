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
   --  Find a buffer from the set of allocate an instance to hold it.
   --  ------------------------------
   function Find_Or_Allocate (Container : in Buffer_Map;
                              Storage   : in Storage_Identifier;
                              Block     : in Block_Number) return Storage_Buffer is
      Buffer : Storage_Buffer;
      Pos    : Buffer_Cursor;
      Key    : constant Storage_Block := Storage_Block '(Storage, Block);
   begin
      Buffer.Block := Key;
      Pos := Container.Find (Key);
      if Buffer_Maps.Has_Element (Pos) then
         Buffer.Data := Buffer_Maps.Element (Pos);
      else
         Buffer.Data := Buffer_Refs.Create;
      end if;
      return Buffer;
   end Find_Or_Allocate;

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
