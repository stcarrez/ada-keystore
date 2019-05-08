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
with Util.Encoders.AES;
with Keystore.IO;
with Ada.Streams;
with Util.Streams;

private package Keystore.Repository.Data is

   --  Set the IV vector to be used for the encryption of the given block number.
   procedure Set_IV (Manager : in out Wallet_Manager;
                     Block   : in IO.Block_Number);

   --  Find the data block instance with the given block number.
   procedure Find_Data_Block (Manager    : in out Wallet_Manager;
                              Block      : in IO.Block_Number;
                              Data_Block : out Wallet_Block_Entry_Access) with
     Post => Data_Block.Available = AES_Align (Data_Block.Available);

   --  Find the data block to hold a new data entry that occupies the given space.
   --  The first data block that has enough space is used otherwise a new block
   --  is allocated and initialized.
   procedure Allocate_Data_Block (Manager    : in out Wallet_Manager;
                                  Space      : in IO.Block_Index;
                                  Data_Block : out Wallet_Block_Entry_Access;
                                  Stream     : in out IO.Wallet_Stream'Class) with
     Post => Data_Block.Available = AES_Align (Data_Block.Available);

   --  Release the data block to the stream.
   procedure Release_Data_Block (Manager    : in out Wallet_Manager;
                                 Data_Block : in out Wallet_Block_Entry_Access;
                                 Stream     : in out IO.Wallet_Stream'Class);

   --  Initialize the data block with an empty content.
   procedure Init_Data_Block (Manager    : in out Wallet_Manager);

   --  Get the fragment position of the item within the data block.
   --  Returns 0 if the data item was not found.
   function Get_Fragment_Position (Data_Block : in Wallet_Block_Entry;
                                   Item       : in Wallet_Entry_Access) return Fragment_Count;

   --  Load the data block in the wallet manager buffer.  Extract the data descriptors
   --  the first time the data block is read.
   procedure Load_Data (Manager    : in out Wallet_Manager;
                        Data_Block : in Wallet_Block_Entry_Access;
                        Stream     : in out IO.Wallet_Stream'Class) with
     Pre => Data_Block.Count > 0;

   --  Save the data block.
   procedure Save_Data (Manager    : in out Wallet_Manager;
                        Data_Block : in out Wallet_Block_Entry;
                        Stream     : in out IO.Wallet_Stream'Class);

   --  Get the data fragment and write it to the output buffer.
   procedure Get_Fragment (Manager  : in out Wallet_Manager;
                           Position : in Fragment_Index;
                           Fragment : in Wallet_Block_Fragment;
                           Output   : out Ada.Streams.Stream_Element_Array);
   procedure Get_Fragment (Manager  : in out Wallet_Manager;
                           Position : in Fragment_Index;
                           Fragment : in Wallet_Block_Fragment;
                           Output   : in out Util.Streams.Output_Stream'Class);

   --  Add in the data block the wallet data entry with its content.
   --  The data block must have been loaded and is not saved.
   procedure Add_Fragment (Manager     : in out Wallet_Manager;
                           Data_Block  : in Wallet_Block_Entry_Access;
                           Item        : in Wallet_Entry_Access;
                           Data_Offset : in Ada.Streams.Stream_Element_Offset;
                           Next_Block  : in Wallet_Block_Entry_Access;
                           Content     : in Ada.Streams.Stream_Element_Array) with
     Pre => DATA_ENTRY_SIZE + AES_Align (Content'Length) <= Data_Block.Available;

   procedure Update_Fragment (Manager     : in out Wallet_Manager;
                              Data_Block  : in Wallet_Block_Entry_Access;
                              Item        : in Wallet_Entry_Access;
                              Data_Offset : in Ada.Streams.Stream_Element_Offset;
                              Position    : in Fragment_Index;
                              Fragment    : in Wallet_Block_Fragment;
                              Next_Block  : in Wallet_Block_Entry_Access;
                              Content     : in Ada.Streams.Stream_Element_Array) with
     Pre => Position <= Data_Block.Count and
     AES_Align (Content'Length) <= Data_Block.Available
     + AES_Align (Data_Block.Fragments (Position).Size);

   --  Delete the data from the data block.
   --  The data block must have been loaded and is not saved.
   procedure Delete_Fragment (Manager    : in out Wallet_Manager;
                              Data_Block : in out Wallet_Block_Entry;
                              Next_Block : out Wallet_Block_Entry_Access;
                              Item       : in Wallet_Entry_Access);

   --  Get the data associated with the named entry.
   procedure Get_Data (Manager    : in out Wallet_Manager;
                       Name       : in String;
                       Result     : out Entry_Info;
                       Output     : out Ada.Streams.Stream_Element_Array;
                       Stream     : in out IO.Wallet_Stream'Class);

   --  Update the data fragments.
   procedure Update_Data (Manager      : in out Wallet_Manager;
                          Item         : in Wallet_Entry_Access;
                          Data_Block   : in out Wallet_Block_Entry_Access;
                          Content      : in Ada.Streams.Stream_Element_Array;
                          Offset       : in out Ada.Streams.Stream_Element_Offset;
                          Full_Block   : in Boolean;
                          New_Block    : out Wallet_Block_Entry_Access;
                          Delete_Block : out Wallet_Block_Entry_Access;
                          Stream       : in out IO.Wallet_Stream'Class);

   --  Erase the data fragments which are not used by the entry.
   procedure Delete_Data (Manager    : in out Wallet_Manager;
                          Item       : in Wallet_Entry_Access;
                          Data_Block : in Wallet_Block_Entry_Access;
                          Stream     : in out IO.Wallet_Stream'Class);

   --  Get the data associated with the named entry and write it in the output stream.
   procedure Write (Manager    : in out Wallet_Manager;
                    Name       : in String;
                    Output     : in out Util.Streams.Output_Stream'Class;
                    Stream     : in out IO.Wallet_Stream'Class);

   --  Write the data in one or several blocks.
   procedure Add_Data (Manager     : in out Wallet_Manager;
                       Item        : in Wallet_Entry_Access;
                       Data_Block  : in out Wallet_Block_Entry_Access;
                       Content     : in Ada.Streams.Stream_Element_Array;
                       Offset      : in out Ada.Streams.Stream_Element_Offset;
                       Full_Block  : in Boolean;
                       Stream      : in out IO.Wallet_Stream'Class);

end Keystore.Repository.Data;
