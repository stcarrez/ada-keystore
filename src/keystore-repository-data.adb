-----------------------------------------------------------------------
--  keystore-repository-data -- Data access and management for the keystore
--  Copyright (C) 2019, 2020, 2022 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
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
   use type Keystore.Repository.Workers.Data_Work_Access;

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
            Work := null;
            exit;
         end if;

         Allocate_Data_Block (Manager, Size, Work);

         Keys.Allocate_Key_Slot (Manager, Iterator, Work.Data_Block, Size,
                                 Work.Key_Pos, Work.Key_Block.Buffer.Block);
         Work.Key_Block.Buffer := Iterator.Current.Buffer;

         Workers.Queue_Cipher_Work (Manager, Work);
         Work := null;

         --  Move on to what remains.
         Data_Offset := Data_Offset + Size;
         Input_Pos := Input_Pos + Size;
      end loop;
      Offset := Interfaces.Unsigned_64 (Data_Offset);
      Workers.Flush_Queue (Manager, null);

   exception
      when E : others =>
         Log.Error ("Exception while encrypting data: ", E);
         if Work /= null then
            Workers.Put_Work (Manager.Workers.all, Work);
         end if;
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

         Workers.Queue_Cipher_Work (Manager, Work);

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
      while Input_Pos <= Content'Last and then Keys.Has_Data_Key (Iterator) loop
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
         Workers.Queue_Cipher_Work (Manager, Work);

         Input_Pos := Input_Pos + Size;
         Data_Offset := Data_Offset + Size;
         exit when Input_Pos > Content'Last;

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
      Mark        : Keys.Data_Key_Marker;
   begin
      Workers.Initialize_Queue (Manager);
      Keys.Mark_Data_Key (Iterator, Mark);
      Keys.Next_Data_Key (Manager, Iterator);
      while Keys.Has_Data_Key (Iterator) loop
         Workers.Allocate_Work (Manager, Workers.DATA_ENCRYPT, null, Iterator, Work);

         --  Fill the work buffer by reading the stream.
         Workers.Fill (Work.all, Content, AES_Align (Iterator.Data_Size), Size);
         if Size = 0 then
            Workers.Put_Work (Manager.Workers.all, Work);

            Delete_Data (Manager, Iterator, Mark);
            exit;
         end if;

         Keys.Update_Key_Slot (Manager, Iterator, Size);
         Work.Key_Block.Buffer := Iterator.Current.Buffer;

         --  Run the encrypt data work either through work manager or through current task.
         Workers.Queue_Cipher_Work (Manager, Work);

         Data_Offset := Data_Offset + Size;

         Keys.Mark_Data_Key (Iterator, Mark);
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
                          Iterator   : in out Keys.Data_Key_Iterator;
                          Mark       : in out Keys.Data_Key_Marker) is
      Work : Workers.Data_Work_Access;
   begin
      while Keys.Has_Data_Key (Iterator) loop
         Workers.Allocate_Work (Manager, Workers.DATA_RELEASE, null, Iterator, Work);

         --  Run the delete data work either through work manager or through current task.
         Workers.Queue_Delete_Work (Manager, Work);

         --  When the last data block was processed, erase the data key.
         if Keys.Is_Last_Key (Iterator) then
            Keys.Delete_Key (Manager, Iterator, Mark);
         end if;
         Keys.Next_Data_Key (Manager, Iterator);
      end loop;
   end Delete_Data;

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
         Workers.Queue_Delete_Work (Manager, Work);

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
      Enqueued : Boolean;
   begin
      Workers.Initialize_Queue (Manager);
      loop
         Keys.Next_Data_Key (Manager, Iterator);
         exit when not Keys.Has_Data_Key (Iterator);
         Workers.Allocate_Work (Manager, Workers.DATA_DECRYPT, Process'Access, Iterator, Work);

         --  Run the decipher work either through work manager or through current task.
         Workers.Queue_Decipher_Work (Manager, Work, Enqueued);
         if not Enqueued then
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
      Enqueued : Boolean;
   begin
      Workers.Initialize_Queue (Manager);
      loop
         Keys.Next_Data_Key (Manager, Iterator);
         exit when not Keys.Has_Data_Key (Iterator);
         Workers.Allocate_Work (Manager, Workers.DATA_DECRYPT, Process'Access, Iterator, Work);

         --  Run the decipher work either through work manager or through current task.
         Workers.Queue_Decipher_Work (Manager, Work, Enqueued);
         if not Enqueued then
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

   --  ------------------------------
   --  Get the data associated with the named entry.
   --  ------------------------------
   procedure Read (Manager  : in out Wallet_Repository;
                   Iterator : in out Keys.Data_Key_Iterator;
                   Offset   : in Ada.Streams.Stream_Element_Offset;
                   Output   : out Ada.Streams.Stream_Element_Array;
                   Last     : out Ada.Streams.Stream_Element_Offset) is
      procedure Process (Work : in Workers.Data_Work_Access);

      Seek_Offset : Stream_Element_Offset := Offset;
      Data_Offset : Stream_Element_Offset := Output'First;

      procedure Process (Work : in Workers.Data_Work_Access) is
         Data_Size : Stream_Element_Offset
           := Work.End_Data - Work.Start_Data + 1 - Work.Seek_Offset;
      begin
         Work.Buffer_Pos := Work.Buffer_Pos + Work.Seek_Offset;
         if Data_Offset + Data_Size - 1 >= Output'Last then
            Data_Size := Output'Last - Data_Offset + 1;
         end if;
         Output (Data_Offset .. Data_Offset + Data_Size - 1)
           := Work.Data (Work.Buffer_Pos .. Work.Buffer_Pos + Data_Size - 1);
         Data_Offset := Data_Offset + Data_Size;
      end Process;

      Work     : Workers.Data_Work_Access;
      Enqueued : Boolean;
      Length   : Stream_Element_Offset := Output'Length;
   begin
      Workers.Initialize_Queue (Manager);
      Keys.Seek (Manager, Seek_Offset, Iterator);
      Length := Length + Seek_Offset;
      while Keys.Has_Data_Key (Iterator) and then Length > 0 loop
         Workers.Allocate_Work (Manager, Workers.DATA_DECRYPT, Process'Access, Iterator, Work);
         Work.Seek_Offset := Seek_Offset;

         --  Run the decipher work either through work manager or through current task.
         Workers.Queue_Decipher_Work (Manager, Work, Enqueued);
         if not Enqueued then
            Process (Work);
         end if;

         exit when Length < Iterator.Data_Size;
         Length := Length - Iterator.Data_Size;
         Seek_Offset := 0;

         Keys.Next_Data_Key (Manager, Iterator);
      end loop;
      Workers.Flush_Queue (Manager, Process'Access);
      Last := Data_Offset - 1;

   exception
      when E : others =>
         Log.Error ("Exception while decrypting data: ", E);
         Workers.Flush_Queue (Manager, null);
         raise;

   end Read;

   --  ------------------------------
   --  Get the data associated with the named entry.
   --  ------------------------------
   procedure Write (Manager  : in out Wallet_Repository;
                    Iterator : in out Keys.Data_Key_Iterator;
                    Offset   : in Ada.Streams.Stream_Element_Offset;
                    Content  : in Ada.Streams.Stream_Element_Array;
                    Result   : in out Interfaces.Unsigned_64) is

      use type Workers.Status_Type;

      Seek_Offset : Stream_Element_Offset := Offset;
      Input_Pos   : Stream_Element_Offset := Content'First;

      Work     : Workers.Data_Work_Access;
      Length   : Stream_Element_Offset := Content'Length;
      Status   : Workers.Status_Type;
   begin
      Workers.Initialize_Queue (Manager);
      Keys.Seek (Manager, Seek_Offset, Iterator);

      --  First part that overlaps an existing data block:
      --  read the current block, update the content.
      if Keys.Has_Data_Key (Iterator) and then Length > 0 then
         Workers.Allocate_Work (Manager, Workers.DATA_DECRYPT, null, Iterator, Work);

         --  Run the decipher work ourselves.
         Work.Do_Decipher_Data;
         Status := Work.Status;
         if Status = Workers.SUCCESS then
            declare
               Data_Size : Stream_Element_Offset
                 := Work.End_Data - Work.Start_Data + 1 - Seek_Offset;
               Pos : constant Stream_Element_Offset
                 := Work.Buffer_Pos + Seek_Offset;
            begin
               if Input_Pos + Data_Size - 1 >= Content'Last then
                  Data_Size := Content'Last - Input_Pos + 1;
               end if;
               Work.Data (Pos .. Pos + Data_Size - 1)
                 := Content (Input_Pos .. Input_Pos + Data_Size - 1);
               Input_Pos := Input_Pos + Data_Size;

               Work.Kind := Workers.DATA_ENCRYPT;
               Work.Status := Workers.PENDING;
               Work.Entry_Id := Iterator.Entry_Id;
               Work.Key_Pos := Iterator.Key_Pos;
               Work.Key_Block.Buffer := Iterator.Current.Buffer;
               Work.Data_Block := Iterator.Data_Block;
               Work.Data_Need_Setup := False;
               Work.Data_Offset := Iterator.Current_Offset;
               Length := Length - Data_Size;

               Keys.Update_Key_Slot (Manager, Iterator, Work.End_Data - Work.Start_Data + 1);
            end;

            --  Run the encrypt data work either through work manager or through current task.
            Workers.Queue_Cipher_Work (Manager, Work);
         else
            Workers.Put_Work (Manager.Workers.all, Work);
            --  Check_Raise_Error (Status);
         end if;

         Keys.Next_Data_Key (Manager, Iterator);
      end if;

      while Keys.Has_Data_Key (Iterator) and then Length >= DATA_MAX_SIZE loop
         Workers.Allocate_Work (Manager, Workers.DATA_ENCRYPT, null, Iterator, Work);

         Work.Buffer_Pos := 1;
         Work.Last_Pos := DATA_MAX_SIZE;
         Work.Data (1 .. DATA_MAX_SIZE) := Content (Input_Pos .. Input_Pos + DATA_MAX_SIZE - 1);
         Keys.Update_Key_Slot (Manager, Iterator, DATA_MAX_SIZE);
         Work.Key_Block.Buffer := Iterator.Current.Buffer;

         --  Run the encrypt data work either through work manager or through current task.
         Workers.Queue_Cipher_Work (Manager, Work);

         Input_Pos := Input_Pos + DATA_MAX_SIZE;
         --  Data_Offset := Data_Offset + DATA_MAX_SIZE;
         Length := Length - DATA_MAX_SIZE;
         exit when Input_Pos > Content'Last;

         Keys.Next_Data_Key (Manager, Iterator);
      end loop;

      --  Last part that overlaps an existing data block:
      --  read the current block, update the content.
      if Keys.Has_Data_Key (Iterator) and then Length > 0 then
         Workers.Allocate_Work (Manager, Workers.DATA_DECRYPT, null, Iterator, Work);

         --  Run the decipher work ourselves.
         Work.Do_Decipher_Data;
         Status := Work.Status;
         if Status = Workers.SUCCESS then
            declare
               Last : constant Stream_Element_Offset
                 := Content'Last - Input_Pos + 1;
            begin
               Work.Data (1 .. Last) := Content (Input_Pos .. Content'Last);
               Input_Pos := Content'Last + 1;
               if Last > Work.End_Data then
                  Work.End_Data := Last;
               end if;

               Work.Kind := Workers.DATA_ENCRYPT;
               Work.Status := Workers.PENDING;
               Work.Entry_Id := Iterator.Entry_Id;
               Work.Key_Pos := Iterator.Key_Pos;
               Work.Key_Block.Buffer := Iterator.Current.Buffer;
               Work.Data_Block := Iterator.Data_Block;
               Work.Data_Need_Setup := False;
               Work.Data_Offset := Iterator.Current_Offset;

               Keys.Update_Key_Slot (Manager, Iterator, Work.End_Data - Work.Start_Data + 1);
            end;

            --  Run the encrypt data work either through work manager or through current task.
            Workers.Queue_Cipher_Work (Manager, Work);
         else
            Workers.Put_Work (Manager.Workers.all, Work);
            --  Check_Raise_Error (Status);
         end if;

         Keys.Next_Data_Key (Manager, Iterator);
      end if;

      Workers.Flush_Queue (Manager, null);
      Result := Iterator.Current_Offset;
      if Input_Pos <= Content'Last then
         Keys.Prepare_Append (Iterator);
         Add_Data (Manager, Iterator, Content (Input_Pos .. Content'Last), Result);
      end if;

   exception
      when E : others =>
         Log.Error ("Exception while decrypting data: ", E);
         Workers.Flush_Queue (Manager, null);
         raise;

   end Write;

end Keystore.Repository.Data;
