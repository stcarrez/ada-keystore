-----------------------------------------------------------------------
--  keystore-passwords-input -- Interactive based password provider
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with Ada.Text_IO;
with Ada.IO_Exceptions;
package body Keystore.Passwords.Input is

   use Ada.Streams;

   --  ------------------------------
   --  Create a password provider that asks interactively for the password.
   --  ------------------------------
   function Create (Message : in String;
                    Confirm : in Boolean) return Provider_Access is
      pragma Unreferenced (Confirm);
      Content : Ada.Streams.Stream_Element_Array (1 .. MAX_PASSWORD_LENGTH);
      C       : Character;
      Length  : Ada.Streams.Stream_Element_Offset := 0;
   begin
      Ada.Text_IO.Put (Message);
      begin
         loop
            Ada.Text_IO.Get_Immediate (C);
            exit when C < ' ';
            Length := Length + 1;
            Content (Length) := Character'Pos (C);
         end loop;

      exception
         when Ada.IO_Exceptions.End_Error =>
            null;
      end;
      Ada.Text_IO.New_Line;
      if Length = 0 then
         raise Keystore.Bad_Password with "Empty password given";
      end if;

      return Create (Content (Content'First .. Length));
   end Create;

end Keystore.Passwords.Input;
