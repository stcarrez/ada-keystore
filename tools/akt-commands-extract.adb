-----------------------------------------------------------------------
--  akt-commands-extract -- Get content from keystore
--  Copyright (C) 2019, 2020 Stephane Carrez
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
with Ada.Command_Line;
with Ada.Directories;
with Ada.Streams.Stream_IO;
with GNAT.Regpat;
with Util.Streams.Raw;
with Util.Systems.Os;
with Util.Files;
with Util.Streams.Files;
package body AKT.Commands.Extract is

   use GNAT.Strings;
   use type Keystore.Entry_Type;

   --  ------------------------------
   --  Get a value from the keystore.
   --  ------------------------------
   overriding
   procedure Execute (Command   : in out Command_Type;
                      Name      : in String;
                      Args      : in Argument_List'Class;
                      Context   : in out Context_Type) is
      pragma Unreferenced (Name);

      Output : Util.Streams.Raw.Raw_Stream;

      procedure Extract_Directory (Path   : in String;
                                   Output : in String);
      procedure Extract_Standard_Output (Name : in String);
      procedure Extract_File (Name   : in String;
                              Output : in String);

      procedure Extract_File (Name   : in String;
                              Output : in String) is
         Target : constant String
           := Util.Files.Compose ((if Output = "" then "." else Output), Name);
         Dir    : constant String
           := Ada.Directories.Containing_Directory (Target);
         File   : Util.Streams.Files.File_Stream;
      begin
         Ada.Directories.Create_Path (Dir);
         File.Create (Mode => Ada.Streams.Stream_IO.Out_File,
                      Name => Target);
         Context.Wallet.Get (Name   => Name,
                             Output => File);

      exception
         when Keystore.Not_Found =>
            AKT.Commands.Log.Error (-("Value '{0}' not found"), Name);
            Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);

      end Extract_File;

      procedure Extract_Directory (Path   : in String;
                                   Output : in String) is
         Pattern : constant GNAT.Regpat.Pattern_Matcher := GNAT.Regpat.Compile (Path & "/.*");
         List    : Keystore.Entry_Map;
         Iter    : Keystore.Entry_Cursor;
      begin
         Context.Wallet.List (Pattern => Pattern,
                              Filter  => (Keystore.T_FILE => True, others => False),
                              Content => List);
         if List.Is_Empty then
            AKT.Commands.Log.Error (-("Value '{0}' not found"), Path);
            Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
            return;
         end if;

         Iter := List.First;
         while Keystore.Entry_Maps.Has_Element (Iter) loop
            declare
               Name : constant String := Keystore.Entry_Maps.Key (Iter);
               Item : constant Keystore.Entry_Info := Keystore.Entry_Maps.Element (Iter);
            begin
               if Item.Kind /= Keystore.T_DIRECTORY then
                  Ada.Text_IO.Put_Line (-("Extract ") & Name);
                  Extract_File (Name, Output);
               end if;
            end;
            Keystore.Entry_Maps.Next (Iter);
         end loop;
      end Extract_Directory;

      procedure Extract_Standard_Output (Name : in String) is
      begin
         Context.Wallet.Get (Name, Output);

      exception
         when Keystore.Not_Found =>
            AKT.Commands.Log.Error (-("Value '{0}' not found"), Name);
            Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);

      end Extract_Standard_Output;

   begin
      Context.Open_Keystore (Args, Use_Worker => True);

      if Context.First_Arg > Args.Get_Count then
         AKT.Commands.Log.Error (-("Missing file or directory to extract"));
         raise Error;
      end if;

      if Command.Use_Stdout then
         Output.Initialize (File => Util.Systems.Os.STDOUT_FILENO);

         for I in Context.First_Arg .. Args.Get_Count loop
            Extract_Standard_Output (Args.Get_Argument (I));
         end loop;
      else
         for I in Context.First_Arg .. Args.Get_Count loop
            declare
               Name : constant String := Args.Get_Argument (I);
               Item : Keystore.Entry_Info;
            begin
               if Context.Wallet.Contains (Name) then
                  Item := Context.Wallet.Find (Name);
                  if Item.Kind = Keystore.T_DIRECTORY then
                     Extract_Directory (Name, Command.Output.all);
                  else
                     Extract_File (Name, Command.Output.all);
                  end if;
               else
                  AKT.Commands.Log.Error (-("Value '{0}' not found"), Name);
                  Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
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
      GC.Define_Switch (Config, Command.Output'Access,
                        "-o:", "--output=",
                        -("Store the result in the output file or directory"));
      GC.Define_Switch (Config => Config,
                        Output => Command.Use_Stdout'Access,
                        Switch => "--",
                        Help => -("Use the standard input to read the content"));
   end Setup;

end AKT.Commands.Extract;
