-----------------------------------------------------------------------
--  akt-commands-extract -- Get content from keystore
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
with Ada.Text_IO;
with Ada.Command_Line;
with Util.Streams.Raw;
with Util.Systems.Os;
package body AKT.Commands.Extract is

   Output : Util.Streams.Raw.Raw_Stream;

   --  ------------------------------
   --  Get a value from the keystore.
   --  ------------------------------
   overriding
   procedure Execute (Command   : in out Command_Type;
                      Name      : in String;
                      Args      : in Argument_List'Class;
                      Context   : in out Context_Type) is
      pragma Unreferenced (Command);
   begin
      if Args.Get_Count /= 1 then
         AKT.Commands.Usage (Args, Context, Name);
      else
         Context.Open_Keystore (Use_Worker => True);
         Output.Initialize (File => Util.Systems.Os.STDOUT_FILENO);
         declare
            Key : constant String := Args.Get_Argument (1);
         begin
            Context.Wallet.Write (Key, Output);

         exception
            when Keystore.Not_Found =>
               AKT.Commands.Log.Error ("Value '{0}' not found", Key);
               Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);

         end;
      end if;
   end Execute;

   --  ------------------------------
   --  Write the help associated with the command.
   --  ------------------------------
   overriding
   procedure Help (Command   : in out Command_Type;
                   Context   : in out Context_Type) is
      pragma Unreferenced (Command, Context);
   begin
      Ada.Text_IO.Put_Line ("akt extract: get a value from the keystore");
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("Usage: extract <name>");
      Ada.Text_IO.New_Line;
      Ada.Text_IO.Put_Line ("  The extract command allows to retrieve the value associated with");
      Ada.Text_IO.Put_Line ("  a wallet entry. It only retrieves one value whose name is passed");
      Ada.Text_IO.Put_Line ("  to the command. This is a shortcut for the `get -n` command.");
   end Help;

end AKT.Commands.Extract;
