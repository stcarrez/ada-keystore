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
with AKT.Passwords;
with Util.Commands;
private with Keystore.Files;
private with Ada.Strings.Unbounded;
private with Ada.Finalization;
private with GNAT.Command_Line;
private with GNAT.Strings;
package AKT.Commands is

   Error : exception;

   subtype Argument_List is Util.Commands.Argument_List;

   type Context_Type is limited private;

   --  Print the command usage.
   procedure Usage (Context : in out Context_Type;
                    Args    : in Argument_List'Class;
                    Name    : in String := "");

   --  Set the keystore path.
   procedure Set_Keystore_Path (Context : in out Context_Type;
                                Path    : in String);

   --  Set the password provider to get a password.
   procedure Set_Password_Provider (Context  : in out Context_Type;
                                    Provider : in AKT.Passwords.Provider_Access);

   --  Open the keystore file using the password password.
   procedure Open_Keystore (Context  : in out Context_Type);

   --  Execute the command with its arguments.
   procedure Execute (Name    : in String;
                      Args    : in Argument_List'Class;
                      Context : in out Context_Type);

   procedure Parse (Context   : in out Context_Type;
                    Arguments : out Util.Commands.Dynamic_Argument_List);

private

   package GC renames GNAT.Command_Line;

   type Context_Type is limited new Ada.Finalization.Limited_Controlled with record
      Wallet            : Keystore.Files.Wallet_File;
      Path              : Ada.Strings.Unbounded.Unbounded_String;
      Provider          : AKT.Passwords.Provider_Access;
      Verbose           : aliased Boolean := False;
      Debug             : aliased Boolean := False;
      Wallet_File       : aliased GNAT.Strings.String_Access;
      Password_File     : aliased GNAT.Strings.String_Access;
      Password_Env      : aliased GNAT.Strings.String_Access;
      Unsafe_Password   : aliased GNAT.Strings.String_Access;
      Password_Socket   : aliased GNAT.Strings.String_Access;
      Command_Config    : GC.Command_Line_Configuration;
   end record;

   --  Initialize the commands.
   overriding
   procedure Initialize (Context : in out Context_Type);

end AKT.Commands;
