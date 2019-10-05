-----------------------------------------------------------------------
--  keystore-repository-workers -- Data access and management for the keystore
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

with Keystore.Random;
with Keystore.Repository.Keys;
with Util.Concurrent.Sequence_Queues;
private package Keystore.Repository.Workers is

   type Wallet_Worker (Work_Count : Natural) is limited private;
   type Wallet_Worker_Access is access all Wallet_Worker;

   --  Create the wallet encryption and decryption work manager.
   function Create (Manager      : access Wallet_Repository;
                    Work_Manager : in Keystore.Task_Manager_Access;
                    Count        : in Positive) return Wallet_Worker_Access;

   subtype Buffer_Offset is Buffers.Buffer_Size range 1 .. DATA_MAX_SIZE;

   type Data_Work_Type is (DATA_ENCRYPT, DATA_DECRYPT, DATA_RELEASE);

   type Status_Type is (SUCCESS, PENDING, IO_ERROR, DATA_CORRUPTION);

   type Data_Work;
   type Data_Work_Access is access all Data_Work;

   package Work_Queues is
     new Util.Concurrent.Sequence_Queues (Element_Type     => Data_Work_Access,
                                          Sequence_Type    => Natural,
                                          Default_Size     => 32,
                                          Clear_On_Dequeue => False);

   type Data_Work is limited new Work_Type with record
      Kind             : Data_Work_Type := DATA_DECRYPT;
      Status           : Status_Type;
      Key_Block        : IO.Marshaller;
      Key_Pos          : IO.Block_Index;
      Data_Block       : IO.Storage_Block;
      Fragment_Count   : Natural;
      Fragment_Pos     : Natural;
      Entry_Id         : Wallet_Entry_Index;
      Data_Offset      : Interfaces.Unsigned_64;
      Data_Need_Setup  : Boolean;
      Sequence         : Natural;
      Start_Data       : Stream_Element_Offset;
      End_Data         : Stream_Element_Offset;
      End_Aligned_Data : Stream_Element_Offset;
      Buffer_Pos       : Buffer_Offset;
      Last_Pos         : Buffer_Offset;
      Random           : Keystore.Random.Generator;
      Data_Decipher    : Util.Encoders.AES.Decoder;
      Data_Cipher      : Util.Encoders.AES.Encoder;
      Info_Cryptor     : Keystore.Keys.Cryptor;
      Stream           : Keystore.IO.Wallet_Stream_Access;
      Queue            : access Work_Queues.Queue;
      Manager          : access Keystore.Repository.Wallet_Repository;
      Data             : aliased Ada.Streams.Stream_Element_Array (1 .. DATA_MAX_SIZE);
   end record;

   overriding
   procedure Execute (Work : in out Data_Work);

   procedure Fill (Work      : in out Data_Work;
                   Input     : in out Util.Streams.Input_Stream'Class;
                   Space     : in Buffer_Offset;
                   Data_Size : out Buffers.Buffer_Size);

   procedure Fill (Work      : in out Data_Work;
                   Input     : in Ada.Streams.Stream_Element_Array;
                   Input_Pos : in Ada.Streams.Stream_Element_Offset;
                   Data_Size : out IO.Buffer_Size);

   procedure Do_Decipher_Data (Work : in out Data_Work);

   procedure Do_Cipher_Data (Work : in out Data_Work);

   procedure Do_Delete_Data (Work : in out Data_Work);

   function Get_Work (Worker : in out Wallet_Worker) return Data_Work_Access;

   procedure Put_Work (Worker : in out Wallet_Worker;
                       Work   : in Data_Work_Access);

   procedure Check_Raise_Error (Work : in Data_Work);

   procedure Allocate_Work (Manager  : in out Wallet_Repository;
                            Kind     : in Data_Work_Type;
                            Process  : access procedure (Work : in Data_Work_Access);
                            Iterator : in Keys.Data_Key_Iterator;
                            Work     : out Data_Work_Access);

   procedure Initialize_Queue (Manager : in out Wallet_Repository);

   procedure Flush_Queue (Manager : in out Wallet_Repository;
                          Process : access procedure (Work : in Data_Work_Access));

   function Queue (Manager : in Wallet_Repository;
                   Work    : in Data_Work_Access) return Boolean;

private

   type Data_Work_Array is array (Positive range <>) of aliased Data_Work;

   type Data_Work_Access_Array is array (Positive range <>) of Data_Work_Access;

   type Wallet_Worker (Work_Count : Natural) is limited record
      Sequence      : Natural := 0;
      Work_Manager  : Keystore.Task_Manager_Access;
      Data_Queue    : aliased Work_Queues.Queue;
      Pool_Count    : Natural := 0;
      Work_Pool     : Data_Work_Access_Array (1 .. Work_Count);
      Work_Slots    : Data_Work_Array (1 .. Work_Count);
   end record;

   procedure Load_Data (Work       : in out Data_Work;
                        Data_Block : in out IO.Marshaller);

end Keystore.Repository.Workers;
