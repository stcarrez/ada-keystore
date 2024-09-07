-----------------------------------------------------------------------
--  keystore-repository-data -- Data access and management for the keystore
--  Copyright (C) 2019, 2020 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with Ada.Streams;
with Util.Streams;
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

   procedure Read (Manager  : in out Wallet_Repository;
                   Iterator : in out Keys.Data_Key_Iterator;
                   Offset   : in Ada.Streams.Stream_Element_Offset;
                   Output   : out Ada.Streams.Stream_Element_Array;
                   Last     : out Ada.Streams.Stream_Element_Offset);

   procedure Write (Manager  : in out Wallet_Repository;
                    Iterator : in out Keys.Data_Key_Iterator;
                    Offset   : in Ada.Streams.Stream_Element_Offset;
                    Content  : in Ada.Streams.Stream_Element_Array;
                    Result   : in out Interfaces.Unsigned_64);

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

   --  Erase the data fragments starting at the key iterator current position.
   procedure Delete_Data (Manager    : in out Wallet_Repository;
                          Iterator   : in out Keys.Data_Key_Iterator;
                          Mark       : in out Keys.Data_Key_Marker);

end Keystore.Repository.Data;
