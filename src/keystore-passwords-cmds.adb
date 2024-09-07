-----------------------------------------------------------------------
--  keystore-passwords-cmds -- External command based password provider
--  Copyright (C) 2019, 2020 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with Util.Processes;
with Util.Streams.Pipes;
package body Keystore.Passwords.Cmds is

   use type Ada.Streams.Stream_Element_Offset;

   --  ------------------------------
   --  Create a password provider that runs a command to get the password.
   --  ------------------------------
   function Create (Command : in String) return Provider_Access is
      Content : Ada.Streams.Stream_Element_Array (1 .. MAX_PASSWORD_LENGTH);
      Last    : Ada.Streams.Stream_Element_Offset := 0;
      Pipe    : aliased Util.Streams.Pipes.Pipe_Stream;
   begin
      Pipe.Open (Command, Util.Processes.READ);
      Pipe.Close;
      Pipe.Read (Content, Last);

      if Pipe.Get_Exit_Status /= 0 then
         raise Keystore.Bad_Password with "External password command exited with status"
           & Natural'Image (Pipe.Get_Exit_Status);
      end if;

      if Last = 0 then
         raise Keystore.Bad_Password with "Empty password given";
      end if;

      return Create (Content (Content'First .. Last));
   end Create;

end Keystore.Passwords.Cmds;
