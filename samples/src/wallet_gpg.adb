-----------------------------------------------------------------------
--  wallet_gpg -- Open wallet protected by GPG and get values
--  Copyright (C) 2020 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with Ada.Text_IO;
with Ada.Command_Line;
with Keystore.Files;
with Keystore.GPG;
with Keystore.Passwords.GPG;

procedure Wallet_GPG is
   Count  : constant Natural := Ada.Command_Line.Argument_Count;
begin
   if Count <= 1 then
      Ada.Text_IO.Put_Line ("Usage: wallet_gpg <keystore-path> {name...}");
      return;
   end if;
   declare
      Path : constant String := Ada.Command_Line.Argument (1);
      WS   : Keystore.Files.Wallet_File;
      Ctx  : Keystore.Passwords.GPG.Context_Type;
   begin
      Keystore.GPG.Open (WS, Ctx, Path);
      for I in 2 .. Count loop
         declare
            Name : constant String := Ada.Command_Line.Argument (I);
         begin
            Ada.Text_IO.Put (Name);
            Ada.Text_IO.Put (" = ");
            if WS.Contains (Name) then
               Ada.Text_IO.Put (WS.Get (Name));
            end if;
            Ada.Text_IO.New_Line;
         end;
      end loop;

   exception
      when Keystore.Bad_Password =>
         Ada.Text_IO.Put_Line ("Invalid password!");

   end;
end Wallet_GPG;
