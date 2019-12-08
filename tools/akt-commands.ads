-----------------------------------------------------------------------
--  akt-commands -- Ada Keystore Tool commands
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
with Keystore.Passwords;
with Keystore.Passwords.GPG;
with Util.Commands;
with Keystore;
private with Util.Log.Loggers;
private with Keystore.Files;
private with Keystore.Passwords.Keys;
private with Ada.Finalization;
private with GNAT.Command_Line;
private with GNAT.Strings;
package AKT.Commands is

   Error : exception;

   subtype Argument_List is Util.Commands.Argument_List;

   type Context_Type is limited private;

   --  Print the command usage.
   procedure Usage (Args    : in Argument_List'Class;
                    Context : in out Context_Type;
                    Name    : in String := "");

   --  Open the keystore file using the password password.
   --  When `Use_Worker` is set, a workers of N tasks is created and assigned to the keystore
   --  for the decryption and encryption process.
   procedure Open_Keystore (Context    : in out Context_Type;
                            Args       : in Argument_List'Class;
                            Use_Worker : in Boolean := False);

   --  Open the keystore file and change the password.
   procedure Change_Password (Context      : in out Context_Type;
                              Args         : in Argument_List'Class;
                              New_Password : in out Keystore.Passwords.Provider'Class;
                              Config       : in Keystore.Wallet_Config;
                              Mode         : in Keystore.Mode_Type);

   --  Execute the command with its arguments.
   procedure Execute (Name    : in String;
                      Args    : in Argument_List'Class;
                      Context : in out Context_Type);

   procedure Parse (Context   : in out Context_Type;
                    Arguments : out Util.Commands.Dynamic_Argument_List);

   procedure Parse_Range (Value  : in String;
                          Config : in out Keystore.Wallet_Config);

   --  Get the keystore file path.
   function Get_Keystore_Path (Context : in out Context_Type;
                               Args    : in Argument_List'Class) return String;

private

   Log     : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("AKT.Commands");

   package GC renames GNAT.Command_Line;

   procedure Initialize (Context : in out Keystore.Passwords.GPG.Context_Type);

   type Context_Type is limited new Ada.Finalization.Limited_Controlled with record
      Wallet            : Keystore.Files.Wallet_File;
      Info              : Keystore.Wallet_Info;
      Config            : Keystore.Wallet_Config := Keystore.Secure_Config;
      Workers           : Keystore.Task_Manager_Access;
      Provider          : Keystore.Passwords.Provider_Access;
      Key_Provider      : Keystore.Passwords.Keys.Key_Provider_Access;
      Slot              : Keystore.Key_Slot;
      Worker_Count      : aliased Integer := 1;
      Version           : aliased Boolean := False;
      Verbose           : aliased Boolean := False;
      Debug             : aliased Boolean := False;
      Dump              : aliased Boolean := False;
      Zero              : aliased Boolean := False;
      Config_File       : aliased GNAT.Strings.String_Access;
      Wallet_File       : aliased GNAT.Strings.String_Access;
      Data_Path         : aliased GNAT.Strings.String_Access;
      Wallet_Key_File   : aliased GNAT.Strings.String_Access;
      Password_File     : aliased GNAT.Strings.String_Access;
      Password_Env      : aliased GNAT.Strings.String_Access;
      Unsafe_Password   : aliased GNAT.Strings.String_Access;
      Password_Socket   : aliased GNAT.Strings.String_Access;
      Password_Command  : aliased GNAT.Strings.String_Access;
      Password_Askpass  : aliased Boolean := False;
      No_Password_Opt   : Boolean := False;
      Command_Config    : GC.Command_Line_Configuration;
      First_Arg         : Positive := 1;
      GPG               : Keystore.Passwords.GPG.Context_Type;
   end record;

   --  Initialize the commands.
   overriding
   procedure Initialize (Context : in out Context_Type);

   overriding
   procedure Finalize (Context : in out Context_Type);

   procedure Setup_Password_Provider (Context : in out Context_Type);

   procedure Setup_Key_Provider (Context : in out Context_Type);

   --  Setup the command before parsing the arguments and executing it.
   procedure Setup (Config  : in out GC.Command_Line_Configuration;
                    Context : in out Context_Type);

end AKT.Commands;
