-----------------------------------------------------------------------
--  keystore-repository-data -- Data access and management for the keystore
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
with Util.Streams;
with Util.Encoders.AES;
with Keystore.IO;
with Keystore.Repository.Keys;

private package Keystore.Repository.Data is

   --  Start offset of the data entry descriptor in the data block.
   function Data_Entry_Offset (Index : in Natural) return IO.Block_Index is
      (IO.BT_DATA_START + Stream_Element_Offset (Index * DATA_ENTRY_SIZE) - DATA_ENTRY_SIZE - 1);

   --  Write the data in one or several blocks.
   procedure Add_Data (Manager     : in out Wallet_Repository;
                       Iterator    : in out Keys.Data_Key_Iterator;
                       Content     : in Ada.Streams.Stream_Element_Array;
                       Offset      : in out Interfaces.Unsigned_64);

   procedure Add_Data (Manager     : in out Wallet_Repository;
                       Iterator    : in out Keys.Data_Key_Iterator;
                       Content     : in out Util.Streams.Input_Stream'Class;
                       Offset      : in out Interfaces.Unsigned_64);

   --  Update the data fragments.
   procedure Update_Data (Manager      : in out Wallet_Repository;
                          Iterator     : in out Keys.Data_Key_Iterator;
                          Content      : in Ada.Streams.Stream_Element_Array;
                          Last_Pos     : out Ada.Streams.Stream_Element_Offset;
                          Offset       : in out Interfaces.Unsigned_64);

   procedure Update_Data (Manager       : in out Wallet_Repository;
                          Iterator      : in out Keys.Data_Key_Iterator;
                          Content       : in out Util.Streams.Input_Stream'Class;
                          End_Of_Stream : out Boolean;
                          Offset        : in out Interfaces.Unsigned_64);

   --  Erase the data fragments starting at the key iterator current position.
   procedure Delete_Data (Manager    : in out Wallet_Repository;
                          Iterator   : in out Keys.Data_Key_Iterator);

   --  Get the data associated with the named entry.
   procedure Get_Data (Manager    : in out Wallet_Repository;
                       Iterator   : in out Keys.Data_Key_Iterator;
                       Output     : out Ada.Streams.Stream_Element_Array);

   --  Get the data associated with the named entry and write it in the output stream.
   procedure Get_Data (Manager    : in out Wallet_Repository;
                       Iterator   : in out Keys.Data_Key_Iterator;
                       Output     : in out Util.Streams.Output_Stream'Class);

private

   --  Find the data block to hold a new data entry that occupies the given space.
   --  The first data block that has enough space is used otherwise a new block
   --  is allocated and initialized.
   procedure Allocate_Data_Block (Manager    : in out Wallet_Repository;
                                  Space      : in IO.Block_Index;
                                  Work       : in Workers.Data_Work_Access);

end Keystore.Repository.Data;
