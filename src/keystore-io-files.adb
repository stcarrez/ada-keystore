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
with Util.Encoders.AES;
package body Keystore.IO.Files is

   protected body Wallet_File_Stream is

      procedure Open (Path : in String) is
      begin
         Block_IO.Open (File => File,
                        Mode => Block_IO.Inout_File,
                        Name => Path);
         Size := Block_IO.Size (File);
      end Open;

      procedure Create (Path : in String) is
      begin
         Block_IO.Create (File => File,
                          Mode => Block_IO.Inout_File,
                          Name => Path);
         Size := 0;
      end Create;

      --  ------------------------------
      --  Read from the wallet stream the block identified by the number and
      --  call the `Process` procedure with the data block content.
      --  ------------------------------
      procedure Read (Block   : in Block_Number;
                      Process : not null access
                        procedure (Data : in Block_Type)) is
      begin
         Block_IO.Read (File => File,
                        Item => Data.Data,
                        From => Positive_Count (Block));
         Process (Data.Data);
      end Read;

      --  ------------------------------
      --  Write in the wallet stream the block identified by the block number.
      --  ------------------------------
      procedure Write (Block   : in Block_Number;
                       Process : not null access
                         procedure (Data : out Block_Type)) is
      begin
         Process (Data.Data);
         Block_IO.Write (File => File,
                         Item => Data.Data,
                         To   => Positive_Count (Block));
      end Write;

      --  ------------------------------
      --  Close the keystore file.
      --  ------------------------------
      procedure Close is
      begin
         if Block_IO.Is_Open (File) then
            Block_IO.Close (File);
         end if;
      end Close;

      --  ------------------------------
      --  Returns true if the block number is allocated.
      --  ------------------------------
      function Is_Used (Block  : in Block_Number) return Boolean is
      begin
         return Positive_Count (Block) <= Size and not Free_Blocks.Contains (Block);
      end Is_Used;

      --  ------------------------------
      --  Allocate a new block and return the block number in `Block`.
      --  ------------------------------
      procedure Allocate (Block  : out Block_Number) is
      begin
         if not Free_Blocks.Is_Empty then
            Block := Free_Blocks.First_Element;
            Free_Blocks.Delete_First;
         else
            Size := Size + 1;
            Block := Block_Number (Size);
         end if;
      end Allocate;

      --  ------------------------------
      --  Release the block number.
      --  ------------------------------
      procedure Release (Block  : in Block_Number) is
      begin
         Free_Blocks.Insert (Block);
      end Release;

   end Wallet_File_Stream;

end Keystore.IO.Files;
