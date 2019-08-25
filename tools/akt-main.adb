-----------------------------------------------------------------------
--  akt-main -- Ada Keystore Tool main procedure
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
with Ada.Command_Line;
with Ada.IO_Exceptions;
with Ada.Exceptions;

with GNAT.Command_Line;

with Util.Log.Loggers;
with Util.Commands;
with AKT.Commands;
with Keystore;
procedure AKT.Main is

   Log     : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("AKT.Main");

   Context     : AKT.Commands.Context_Type;
   Arguments   : Util.Commands.Dynamic_Argument_List;
begin
   AKT.Configure_Logs (Debug => False, Verbose => False);

   AKT.Commands.Parse (Context, Arguments);

exception
   when GNAT.Command_Line.Exit_From_Command_Line | GNAT.Command_Line.Invalid_Switch =>
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);

   when Keystore.Bad_Password =>
      Log.Error ("Invalid password to unlock the keystore file");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);

   when Keystore.No_Key_Slot =>
      Log.Error ("There is no available key slot to add the password");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);

   when Keystore.Corrupted =>
      Log.Error ("The keystore file is corrupted: invalid meta data content");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);

   when Keystore.Invalid_Block =>
      Log.Error ("The keystore file is corrupted: invalid data block headers or signature");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);

   when Keystore.Invalid_Storage =>
      Log.Error ("The keystore file is corrupted: invalid or missing storage file");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);

   when AKT.Commands.Error | Util.Commands.Not_Found =>
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);

   when E : Ada.IO_Exceptions.Name_Error =>
      Log.Error ("Cannot access file: {0}", Ada.Exceptions.Exception_Message (E));
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);

   when E : others =>
      Log.Error ("Some internal error occurred", E);
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);

end AKT.Main;
