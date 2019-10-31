-----------------------------------------------------------------------
--  akt-commands-store -- Store content read from standard input in keystore
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
with Util.Systems.Os;
with Util.Streams.Raw;
package body AKT.Commands.Store is

   Input : Util.Streams.Raw.Raw_Stream;

   --  ------------------------------
   --  Insert a new value in the keystore.
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
         Input.Initialize (File => Util.Systems.Os.STDIN_FILENO);
         Context.Open_Keystore (Use_Worker => True);
         Context.Wallet.Set (Name  => Args.Get_Argument (1),
                             Kind  => Keystore.T_BINARY,
                             Input => Input);
      end if;
   end Execute;

end AKT.Commands.Store;
