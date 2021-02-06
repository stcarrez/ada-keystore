-----------------------------------------------------------------------
--  akt-commands-store -- Store content read from standard input in keystore
--  Copyright (C) 2019, 2021 Stephane Carrez
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
with Ada.Text_IO;
with Ada.Directories;
with Ada.Streams.Stream_IO;
with Util.Systems.Os;
with Util.Streams.Raw;
with Util.Streams.Files;
with Keystore.Tools;
package body AKT.Commands.Store is

   use Ada.Directories;

   --  ------------------------------
   --  Insert a new value in the keystore.
   --  ------------------------------
   overriding
   procedure Execute (Command   : in out Command_Type;
                      Name      : in String;
                      Args      : in Argument_List'Class;
                      Context   : in out Context_Type) is
      pragma Unreferenced (Name);

      function Accept_File (Ent : in Keystore.Tools.Directory_Entry_Type) return Boolean;
      procedure Insert_File (Name : in String);
      procedure Insert_Directory (Name : in String);
      procedure Insert_Standard_Input (Name : in String);

      function Accept_File (Ent : in Keystore.Tools.Directory_Entry_Type) return Boolean is
      begin
         Ada.Text_IO.Put_Line (Ada.Directories.Full_Name (Ent));
         return True;
      end Accept_File;

      procedure Insert_File (Name : in String) is
         File : Util.Streams.Files.File_Stream;
      begin
         File.Open (Mode => Ada.Streams.Stream_IO.In_File,
                    Name => Name);

         Context.Wallet.Set (Name  => Ada.Directories.Simple_Name (Name),
                             Kind  => Keystore.T_FILE,
                             Input => File);
      end Insert_File;

      procedure Insert_Directory (Name : in String) is
      begin
         Keystore.Tools.Store (Wallet  => Context.Wallet,
                               Path    => Name,
                               Prefix  => Ada.Directories.Simple_Name (Name) & '/',
                               Pattern => "*",
                               Filter  => Accept_File'Access);
      end Insert_Directory;

      procedure Insert_Standard_Input (Name : in String) is
         Input : Util.Streams.Raw.Raw_Stream;
      begin
         Input.Initialize (File => Util.Systems.Os.STDIN_FILENO);
         Context.Wallet.Set (Name  => Name,
                             Kind  => Keystore.T_BINARY,
                             Input => Input);
      end Insert_Standard_Input;

   begin
      --  Open keystore with workers because we expect possibly big data.
      Context.Open_Keystore (Args, Use_Worker => True);

      if Command.Use_Stdin then
         if Context.First_Arg > Args.Get_Count then
            AKT.Commands.Log.Error (-("missing name to store the standard input"));
            raise Error;
         end if;

         Insert_Standard_Input (Args.Get_Argument (Context.First_Arg));
      else
         for I in Context.First_Arg .. Args.Get_Count loop
            declare
               Name : constant String := Args.Get_Argument (I);
            begin
               if not Ada.Directories.Exists (Name) then
                  AKT.Commands.Log.Error (-("'{0}' does not exist"), Name);
                  raise Error;

               elsif Ada.Directories.Kind (Name) = Ada.Directories.Ordinary_File then
                  Insert_File (Name);

               elsif Ada.Directories.Kind (Name) = Ada.Directories.Directory then
                  Insert_Directory (Name);

               else
                  AKT.Commands.Log.Error (-("'{0}' is not a regular file nor a directory"), Name);
                  raise Error;

               end if;
            end;
         end loop;
      end if;
   end Execute;

   --  ------------------------------
   --  Setup the command before parsing the arguments and executing it.
   --  ------------------------------
   procedure Setup (Command : in out Command_Type;
                    Config  : in out GNAT.Command_Line.Command_Line_Configuration;
                    Context : in out Context_Type) is
      package GC renames GNAT.Command_Line;
   begin
      Drivers.Command_Type (Command).Setup (Config, Context);
      GC.Define_Switch (Config => Config,
                        Output => Command.Use_Stdin'Access,
                        Switch => "--",
                        Help => -("Use the standard input to read the content"));
   end Setup;

end AKT.Commands.Store;
