-----------------------------------------------------------------------
--  keystore -- Ada keystore
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

with Util.Log.Loggers;
package body Keystore is

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Keystore");

   function To_String (UUID : in UUID_Type) return String is
      Encode : constant Util.Encoders.Encoder := Util.Encoders.Create ("hex");
      U1     : constant String := Encode.Encode_Unsigned_32 (UUID (1));
      U2     : constant String := Encode.Encode_Unsigned_32 (UUID (2));
      U3     : constant String := Encode.Encode_Unsigned_32 (UUID (3));
      U4     : constant String := Encode.Encode_Unsigned_32 (UUID (4));
   begin
      return U1 & "-"
        & U2 (U2'First .. U2'First + 3) & "-"
        & U2 (U2'First + 4 .. U2'Last) & "-"
        & U3 (U3'First .. U3'First + 3) & "-"
        & U3 (U3'First + 4 .. U3'Last) & U4;
   end To_String;

   --  ------------------------------
   --  Add in the wallet the named entry and associate it the content.
   --  The content is encrypted in AES-CBC with a secret key and an IV vector
   --  that is created randomly for the new named entry.
   --  ------------------------------
   procedure Add (Container : in out Wallet;
                  Name      : in String;
                  Content   : in String) is
      use Ada.Streams;

      Data : Stream_Element_Array (Stream_Element_Offset (Content'First)
                                   .. Stream_Element_Offset (Content'Last));
      for Data'Address use Content'Address;
   begin
      Wallet'Class (Container).Add (Name, T_STRING, Data);
   end Add;

   --  ------------------------------
   --  Add or update in the wallet the named entry and associate it the content.
   --  The content is encrypted in AES-CBC with a secret key and an IV vector
   --  that is created randomly for the new or updated named entry.
   --  ------------------------------
   procedure Set (Container : in out Wallet;
                  Name      : in String;
                  Content   : in String) is
      use Ada.Streams;

      Data : Stream_Element_Array (Stream_Element_Offset (Content'First)
                                   .. Stream_Element_Offset (Content'Last));
      for Data'Address use Content'Address;
   begin
      Wallet'Class (Container).Set (Name, T_STRING, Data);
   end Set;

   --  ------------------------------
   --  Update in the wallet the named entry and associate it the new content.
   --  The secret key and IV vectors are not changed.
   --  ------------------------------
   procedure Update (Container : in out Wallet;
                     Name      : in String;
                     Content   : in String) is
      use Ada.Streams;

      Data : Stream_Element_Array (Stream_Element_Offset (Content'First)
                                   .. Stream_Element_Offset (Content'Last));
      for Data'Address use Content'Address;
   begin
      Wallet'Class (Container).Update (Name, T_STRING, Data);
   end Update;

   --  ------------------------------
   --  Get from the wallet the named entry.
   --  ------------------------------
   function Get (Container : in out Wallet;
                 Name      : in String) return String is
      use Ada.Streams;

      Info   : Entry_Info := Wallet'Class (Container).Find (Name);
      Result : String (1 .. Natural (Info.Size));
      Buffer : Stream_Element_Array (1 .. Stream_Element_Offset (Info.Size));
      for Buffer'Address use Result'Address;
   begin
      Wallet'Class (Container).Get (Name, Info, Buffer);
      return Result;
   end Get;

   --  ------------------------------
   --  Start the tasks of the task manager.
   --  ------------------------------
   procedure Start (Manager : in Task_Manager_Access) is
   begin
      Manager.Start;
   end Start;

   --  ------------------------------
   --  Stop the tasks.
   --  ------------------------------
   procedure Stop (Manager : in Task_Manager_Access) is
   begin
      Manager.Stop;
   end Stop;

   procedure Execute (Manager : in out Task_Manager;
                      Work    : in Work_Type_Access) is
   begin
      Executors.Execute (Executors.Executor_Manager (Manager), Work);
   end Execute;

   procedure Execute (Work : in out Work_Type_Access) is
   begin
      Work.Execute;
   end Execute;

   procedure Error (Work : in out Work_Type_Access;
                    Ex   : in Ada.Exceptions.Exception_Occurrence) is
      pragma Unreferenced (Work);
   begin
      Log.Error ("Work error", Ex);
   end Error;

end Keystore;
