-----------------------------------------------------------------------
--  keystore-passwords-cmds -- External command based password provider
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
with Ada.Strings.Unbounded;
with Util.Processes;
with Util.Streams.Pipes;
with Util.Streams.Buffered;
package body Keystore.Passwords.Cmds is

   type Provider (Len : Natural) is limited new Keystore.Passwords.Provider with record
      Command : String (1 .. Len);
   end record;

   --  Get the password through the Getter operation.
   overriding
   procedure Get_Password (From   : in Provider;
                           Getter : not null access procedure (Password : in Secret_Key));

   --  ------------------------------
   --  Create a password provider that reads runs a command to get the password.
   --  ------------------------------
   function Create (Command : in String) return Provider_Access is
   begin
      return new Provider '(Len => Command'Length, Command => Command);
   end Create;

   --  ------------------------------
   --  Get the password through the Getter operation.
   --  ------------------------------
   overriding
   procedure Get_Password (From   : in Provider;
                           Getter : not null access procedure (Password : in Secret_Key)) is
      Pipe    : aliased Util.Streams.Pipes.Pipe_Stream;
      Buffer  : Util.Streams.Buffered.Input_Buffer_Stream;
      Content : Ada.Strings.Unbounded.Unbounded_String;
   begin
      Pipe.Open (From.Command, Util.Processes.READ);
      Buffer.Initialize (Pipe'Access, 1024);
      Buffer.Read (Content);
      Pipe.Close;

      if Pipe.Get_Exit_Status /= 0 then
         raise Keystore.Bad_Password with "External password command exited with status"
           & Natural'Image (Pipe.Get_Exit_Status);
      end if;

      if Ada.Strings.Unbounded.Length (Content) = 0 then
         raise Keystore.Bad_Password with "Operation canceled";
      end if;

      Getter (Keystore.Create (Ada.Strings.Unbounded.To_String (Content)));
   end Get_Password;

end Keystore.Passwords.Cmds;
