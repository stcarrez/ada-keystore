-----------------------------------------------------------------------
--  keystore-repository-keys -- Data keys management
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
with Keystore.Marshallers;
private package Keystore.Repository.Keys is

   type Data_Key_Iterator is limited record
      Current        : Marshallers.Marshaller;
      Current_Offset : Interfaces.Unsigned_64;
      Entry_Id       : Wallet_Entry_Index;
      Item           : Wallet_Entry_Access;
      Data_Block     : IO.Storage_Block;
      Directory      : Wallet_Directory_Entry_Access;
      Key_Iter       : Wallet_Data_Key_List.Cursor;
      Data_Size      : Stream_Element_Offset;
      Count          : Interfaces.Unsigned_16;
      Key_Count      : Interfaces.Unsigned_16;
      Key_Pos        : IO.Block_Index;
      Key_Header_Pos : IO.Block_Index;
      Key_Last_Pos   : IO.Block_Index;
   end record;

   type Data_Key_Marker is limited record
      Directory      : Wallet_Directory_Entry_Access;
      Key_Header_Pos : IO.Block_Index;
      Key_Count      : Interfaces.Unsigned_16;
   end record;

   subtype Wallet_Manager is Wallet_Repository;

   procedure Initialize (Manager  : in out Wallet_Manager;
                         Iterator : in out Data_Key_Iterator;
                         Item     : in Wallet_Entry_Access);

   function Has_Data_Key (Iterator : in Data_Key_Iterator) return Boolean;

   function Is_Last_Key (Iterator : in Data_Key_Iterator) return Boolean;

   procedure Mark_Data_Key (Iterator : in Data_Key_Iterator;
                            Mark     : in out Data_Key_Marker);

   procedure Next_Data_Key (Manager  : in out Wallet_Repository;
                            Iterator : in out Data_Key_Iterator);

   procedure Delete_Key (Manager  : in out Wallet_Repository;
                         Iterator : in out Data_Key_Iterator;
                         Mark     : in out Data_Key_Marker);

   procedure Allocate_Key_Slot (Manager    : in out Wallet_Repository;
                                Iterator   : in out Data_Key_Iterator;
                                Data_Block : in IO.Storage_Block;
                                Size       : in IO.Buffer_Size;
                                Key_Pos    : out IO.Block_Index;
                                Key_Block  : out IO.Storage_Block);

   procedure Update_Key_Slot (Manager    : in out Wallet_Repository;
                              Iterator   : in out Data_Key_Iterator;
                              Size       : in IO.Buffer_Size);

private

   use type Interfaces.Unsigned_16;

   function Key_Slot_Size (Count : in Interfaces.Unsigned_16) return IO.Block_Index is
      (IO.Block_Index (DATA_KEY_ENTRY_SIZE * Count));

   procedure Load_Next_Keys (Manager  : in out Wallet_Manager;
                             Iterator : in out Data_Key_Iterator);

end Keystore.Repository.Keys;
