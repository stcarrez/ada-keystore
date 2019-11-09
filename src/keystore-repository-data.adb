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
with Interfaces;
with Util.Log.Loggers;
with Keystore.Logs;
with Keystore.Repository.Workers;

--  === Data Block ===
--
--  Data block start is encrypted with wallet data key, data fragments are
--  encrypted with their own key.  Loading and saving data blocks occurs exclusively
--  from the workers package.  The data block can be stored in a separate file so that
--  the wallet repository and its keys are separate from the data blocks.
--
--  ```
--  +------------------+
--  | 03 03            | 2b
--  | Encrypt size     | 2b = DATA_ENTRY_SIZE * Nb data fragment
--  | Wallet id        | 4b
--  | PAD 0            | 4b
--  | PAD 0            | 4b
--  +------------------+-----
--  | Entry ID         | 4b  Encrypted with wallet id
--  | Slot size        | 2b
--  | 0 0              | 2b
--  | Data offset      | 8b
--  | Content HMAC-256 | 32b => 48b = DATA_ENTRY_SIZE
--  +------------------+
--  | ...              |
--  +------------------+-----
--  | ...              |
--  +------------------+
--  | Data content     |     Encrypted with data entry key
--  +------------------+-----
--  | Block HMAC-256   | 32b
--  +------------------+
--  ```
--
package body Keystore.Repository.Data is

   use type Interfaces.Unsigned_64;

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Keystore.Repository.Data");

   --  ------------------------------
   --  Find the data block to hold a new data entry that occupies the given space.
   --  The first data block that has enough space is used otherwise a new block
   --  is allocated and initialized.
   --  ------------------------------
   procedure Allocate_Data_Block (Manager    : in out Wallet_Repository;
                                  Space      : in IO.Block_Index;
                                  Work       : in Workers.Data_Work_Access) is
      pragma Unreferenced (Space);
   begin
      Manager.Stream.Allocate (IO.DATA_BLOCK, Work.Data_Block);
      Work.Data_Need_Setup := True;

      Logs.Debug (Log, "Allocated data block{0}", Work.Data_Block);
   end Allocate_Data_Block;

   --  ------------------------------
   --  Write the data in one or several blocks.
   --  ------------------------------
   procedure Add_Data (Manager     : in out Wallet_Repository;
                       Iterator    : in out Keys.Data_Key_Iterator;
                       Content     : in Ada.Streams.Stream_Element_Array;
                       Offset      : in out Interfaces.Unsigned_64) is
      Size        : IO.Buffer_Size;
      Input_Pos   : Stream_Element_Offset := Content'First;
      Data_Offset : Stream_Element_Offset := Stream_Element_Offset (Offset);
      Work        : Workers.Data_Work_Access;
   begin
      Workers.Initialize_Queue (Manager);
      while Input_Pos <= Content'Last loop
         --  Get a data work instance or flush pending works to make one available.
         Workers.Allocate_Work (Manager, Workers.DATA_ENCRYPT, null, Iterator, Work);

         Workers.Fill (Work.all, Content, Input_Pos, Size);
         if Size = 0 then
            Workers.Put_Work (Manager.Workers.all, Work);
            exit;
         end if;

         Allocate_Data_Block (Manager, Size, Work);

         Keys.Allocate_Key_Slot (Manager, Iterator, Work.Data_Block, Size,
                                 Work.Key_Pos, Work.Key_Block.Buffer.Block);
         Work.Key_Block.Buffer := Iterator.Current.Buffer;

         if not Workers.Queue (Manager, Work) then
            Work.Do_Cipher_Data;
            Workers.Put_Work (Manager.Workers.all, Work);
            Work.Check_Raise_Error;
         end if;

         --  Move on to what remains.
         Data_Offset := Data_Offset + Size;
         Input_Pos := Input_Pos + Size;
      end loop;
      Offset := Interfaces.Unsigned_64 (Data_Offset);
      Workers.Flush_Queue (Manager, null);

   exception
      when E : others =>
         Log.Error ("Exception while encrypting data: ", E);
         Workers.Flush_Queue (Manager, null);
         raise;

   end Add_Data;

   --  ------------------------------
   --  Write the data in one or several blocks.
   --  ------------------------------
   procedure Add_Data (Manager     : in out Wallet_Repository;
                       Iterator    : in out Keys.Data_Key_Iterator;
                       Content     : in out Util.Streams.Input_Stream'Class;
                       Offset      : in out Interfaces.Unsigned_64) is
      Size        : IO.Buffer_Size;
      Data_Offset : Stream_Element_Offset := Stream_Element_Offset (Offset);
      Work        : Workers.Data_Work_Access;
   begin
      Workers.Initialize_Queue (Manager);
      loop
         --  Get a data work instance or flush pending works to make one available.
         Workers.Allocate_Work (Manager, Workers.DATA_ENCRYPT, null, Iterator, Work);

         --  Fill the work buffer by reading the stream.
         Workers.Fill (Work.all, Content, DATA_MAX_SIZE, Size);
         if Size = 0 then
            Workers.Put_Work (Manager.Workers.all, Work);
            exit;
         end if;

         Allocate_Data_Block (Manager, DATA_MAX_SIZE, Work);

         Keys.Allocate_Key_Slot (Manager, Iterator, Work.Data_Block, Size,
                                 Work.Key_Pos, Work.Key_Block.Buffer.Block);
         Work.Key_Block.Buffer := Iterator.Current.Buffer;

         if not Workers.Queue (Manager, Work) then
            Work.Do_Cipher_Data;
            Workers.Put_Work (Manager.Workers.all, Work);
            Work.Check_Raise_Error;
         end if;

         --  Move on to what remains.
         Data_Offset := Data_Offset + Size;
      end loop;
      Offset := Interfaces.Unsigned_64 (Data_Offset);
      Workers.Flush_Queue (Manager, null);

   exception
      when E : others =>
         Log.Error ("Exception while encrypting data: ", E);
         Workers.Flush_Queue (Manager, null);
         raise;

   end Add_Data;

   procedure Update_Data (Manager    : in out Wallet_Repository;
                          Iterator   : in out Keys.Data_Key_Iterator;
                          Content    : in Ada.Streams.Stream_Element_Array;
                          Last_Pos   : out Ada.Streams.Stream_Element_Offset;
                          Offset     : in out Interfaces.Unsigned_64) is
      Size        : Stream_Element_Offset;
      Input_Pos   : Stream_Element_Offset := Content'First;
      Work        : Workers.Data_Work_Access;
      Data_Offset : Stream_Element_Offset := Stream_Element_Offset (Offset);
   begin
      Workers.Initialize_Queue (Manager);
      Keys.Next_Data_Key (Manager, Iterator);
      while Input_Pos <= Content'Last and Keys.Has_Data_Key (Iterator) loop
         Workers.Allocate_Work (Manager, Workers.DATA_ENCRYPT, null, Iterator, Work);

         Size := Content'Last - Input_Pos + 1;
         if Size > DATA_MAX_SIZE then
            Size := DATA_MAX_SIZE;
         end if;
         if Size > AES_Align (Iterator.Data_Size) then
            Size := AES_Align (Iterator.Data_Size);
         end if;
         Work.Buffer_Pos := 1;
         Work.Last_Pos := Size;
         Work.Data (1 .. Size) := Content (Input_Pos .. Input_Pos + Size - 1);
         Keys.Update_Key_Slot (Manager, Iterator, Size);
         Work.Key_Block.Buffer := Iterator.Current.Buffer;

         --  Run the encrypt data work either through work manager or through current task.
         if not Workers.Queue (Manager, Work) then
            Work.Do_Cipher_Data;
            Workers.Put_Work (Manager.Workers.all, Work);
            Work.Check_Raise_Error;
         end if;

         Input_Pos := Input_Pos + Size;
         Data_Offset := Data_Offset + Size;

         Keys.Next_Data_Key (Manager, Iterator);
      end loop;

      Workers.Flush_Queue (Manager, null);
      Offset := Interfaces.Unsigned_64 (Data_Offset);
      Last_Pos := Input_Pos;
      if Input_Pos <= Content'Last then
         Keys.Prepare_Append (Iterator);
      end if;

   exception
      when E : others =>
         Log.Error ("Exception while encrypting data: ", E);
         Workers.Flush_Queue (Manager, null);
         raise;

   end Update_Data;

   procedure Update_Data (Manager       : in out Wallet_Repository;
                          Iterator      : in out Keys.Data_Key_Iterator;
                          Content       : in out Util.Streams.Input_Stream'Class;
                          End_Of_Stream : out Boolean;
                          Offset        : in out Interfaces.Unsigned_64) is
      Work        : Workers.Data_Work_Access;
      Size        : IO.Buffer_Size := 0;
      Data_Offset : Stream_Element_Offset := Stream_Element_Offset (Offset);
   begin
      Workers.Initialize_Queue (Manager);
      Keys.Next_Data_Key (Manager, Iterator);
      while Keys.Has_Data_Key (Iterator) loop
         Workers.Allocate_Work (Manager, Workers.DATA_ENCRYPT, null, Iterator, Work);

         --  Fill the work buffer by reading the stream.
         Workers.Fill (Work.all, Content, AES_Align (Iterator.Data_Size), Size);
         if Size = 0 then
            Workers.Put_Work (Manager.Workers.all, Work);
            exit;
         end if;

         Keys.Update_Key_Slot (Manager, Iterator, Size);
         Work.Key_Block.Buffer := Iterator.Current.Buffer;

         --  Run the encrypt data work either through work manager or through current task.
         if not Workers.Queue (Manager, Work) then
            Work.Do_Cipher_Data;
            Workers.Put_Work (Manager.Workers.all, Work);
            Work.Check_Raise_Error;
         end if;

         Data_Offset := Data_Offset + Size;

         Keys.Next_Data_Key (Manager, Iterator);
      end loop;

      Workers.Flush_Queue (Manager, null);
      Offset := Interfaces.Unsigned_64 (Data_Offset);
      End_Of_Stream := Size = 0;
      if not End_Of_Stream then
         Keys.Prepare_Append (Iterator);
      end if;

   exception
      when E : others =>
         Log.Error ("Exception while encrypting data: ", E);
         Workers.Flush_Queue (Manager, null);
         raise;

   end Update_Data;

   --  ------------------------------
   --  Erase the data fragments starting at the key iterator current position.
   --  ------------------------------
   procedure Delete_Data (Manager    : in out Wallet_Repository;
                          Iterator   : in out Keys.Data_Key_Iterator) is
      Work : Workers.Data_Work_Access;
      Mark : Keys.Data_Key_Marker;
   begin
      Keys.Mark_Data_Key (Iterator, Mark);
      Workers.Initialize_Queue (Manager);
      loop
         Keys.Next_Data_Key (Manager, Iterator);
         exit when not Keys.Has_Data_Key (Iterator);
         Workers.Allocate_Work (Manager, Workers.DATA_RELEASE, null, Iterator, Work);

         --  Run the delete data work either through work manager or through current task.
         if not Workers.Queue (Manager, Work) then
            Work.Do_Delete_Data;
            Workers.Put_Work (Manager.Workers.all, Work);
            Work.Check_Raise_Error;
         end if;

         --  When the last data block was processed, erase the data key.
         if Keys.Is_Last_Key (Iterator) then
            Keys.Delete_Key (Manager, Iterator, Mark);
         end if;
      end loop;
      Workers.Flush_Queue (Manager, null);

   exception
      when E : others =>
         Log.Error ("Exception while deleting data: ", E);
         Workers.Flush_Queue (Manager, null);
         raise;

   end Delete_Data;

   --  ------------------------------
   --  Get the data associated with the named entry.
   --  ------------------------------
   procedure Get_Data (Manager    : in out Wallet_Repository;
                       Iterator   : in out Keys.Data_Key_Iterator;
                       Output     : out Ada.Streams.Stream_Element_Array) is
      procedure Process (Work : in Workers.Data_Work_Access);

      Data_Offset : Stream_Element_Offset := Output'First;

      procedure Process (Work : in Workers.Data_Work_Access) is
         Data_Size : constant Stream_Element_Offset := Work.End_Data - Work.Start_Data + 1;
      begin
         Output (Data_Offset .. Data_Offset + Data_Size - 1)
           := Work.Data (Work.Buffer_Pos .. Work.Buffer_Pos + Data_Size - 1);
         Data_Offset := Data_Offset + Data_Size;
      end Process;

      Work     : Workers.Data_Work_Access;
   begin
      Workers.Initialize_Queue (Manager);
      loop
         Keys.Next_Data_Key (Manager, Iterator);
         exit when not Keys.Has_Data_Key (Iterator);
         Workers.Allocate_Work (Manager, Workers.DATA_DECRYPT, Process'Access, Iterator, Work);

         --  Run the decipher work either through work manager or through current task.
         if not Workers.Queue (Manager, Work) then
            Work.Do_Decipher_Data;
            Workers.Put_Work (Manager.Workers.all, Work);
            Work.Check_Raise_Error;
            Process (Work);
         end if;

      end loop;
      Workers.Flush_Queue (Manager, Process'Access);

   exception
      when E : others =>
         Log.Error ("Exception while decrypting data: ", E);
         Workers.Flush_Queue (Manager, null);
         raise;

   end Get_Data;

   procedure Get_Data (Manager    : in out Wallet_Repository;
                       Iterator   : in out Keys.Data_Key_Iterator;
                       Output     : in out Util.Streams.Output_Stream'Class) is
      procedure Process (Work : in Workers.Data_Work_Access);

      procedure Process (Work : in Workers.Data_Work_Access) is
      begin
         Output.Write (Work.Data (Work.Buffer_Pos .. Work.Last_Pos));
      end Process;

      Work     : Workers.Data_Work_Access;
   begin
      Workers.Initialize_Queue (Manager);
      loop
         Keys.Next_Data_Key (Manager, Iterator);
         exit when not Keys.Has_Data_Key (Iterator);
         Workers.Allocate_Work (Manager, Workers.DATA_DECRYPT, Process'Access, Iterator, Work);

         --  Run the decipher work either through work manager or through current task.
         if not Workers.Queue (Manager, Work) then
            Work.Do_Decipher_Data;
            Workers.Put_Work (Manager.Workers.all, Work);
            Work.Check_Raise_Error;
            Process (Work);
         end if;

      end loop;
      Workers.Flush_Queue (Manager, Process'Access);

   exception
      when E : others =>
         Log.Error ("Exception while decrypting data: ", E);
         Workers.Flush_Queue (Manager, null);
         raise;

   end Get_Data;

end Keystore.Repository.Data;
