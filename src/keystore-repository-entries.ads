-----------------------------------------------------------------------
--  keystore-repository-entries -- Repository management for the keystore
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

private package Keystore.Repository.Entries is

   --  Load the wallet directory block in the wallet manager buffer.
   --  Extract the directory if this is the first time the data block is read.
   procedure Load_Directory (Manager   : in out Wallet_Manager;
                             Dir_Block : in Wallet_Directory_Entry_Access;
                             Stream    : in out IO.Wallet_Stream'Class);

   --  Load the complete wallet directory by starting at the given block.
   procedure Load_Complete_Directory (Manager : in out Wallet_Manager;
                                      Block   : in Keystore.IO.Block_Number;
                                      Stream  : in out IO.Wallet_Stream'Class);

   --  Find and load a directory block to hold a new entry that occupies the given space.
   --  The first directory block that has enough space is used otherwise a new block
   --  is allocated and initialized.
   procedure Find_Directory_Block (Manager     : in out Wallet_Manager;
                                   Space       : in IO.Block_Index;
                                   Entry_Block : out Wallet_Directory_Entry_Access;
                                   Stream      : in out IO.Wallet_Stream'Class);

   --  Add a new entry in the wallet directory.
   procedure Add_Entry (Manager : in out Wallet_Manager;
                        Name    : in String;
                        Kind    : in Entry_Type;
                        Size    : in Interfaces.Unsigned_64;
                        Item    : out Wallet_Entry_Access;
                        Stream  : in out IO.Wallet_Stream'Class);

   --  Update an existing entry in the wallet directory.
   procedure Update_Entry (Manager : in out Wallet_Manager;
                           Item    : in Wallet_Entry_Access;
                           Kind    : in Entry_Type;
                           Size    : in Interfaces.Unsigned_64;
                           Stream  : in out IO.Wallet_Stream'Class);

   --  Delete the entry from the repository.
   procedure Delete_Entry (Manager    : in out Wallet_Manager;
                           Item       : in Wallet_Entry_Access;
                           Stream     : in out IO.Wallet_Stream'Class);

end Keystore.Repository.Entries;
