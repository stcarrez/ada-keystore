-----------------------------------------------------------------------
--  akt-commands-otp -- One-time-password generation with otpauth
--  Copyright (C) 2023 Stephane Carrez
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
with Ada.Calendar.Conversions;
with Util.Strings;
with Interfaces.C;
with GNAT.Command_Line;
with Util.Encoders.HMAC.SHA1;
with Util.Encoders.HMAC.SHA256;
with Util.Encoders.HMAC.HOTP;
package body AKT.Commands.OTP is

   use type Interfaces.C.long;

   procedure Generate (Account : in String;
                       URI     : in String;
                       Context : in out Context_Type);
   function Get_Account (URI : in String) return String;
   function Get_Param (URI  : in String;
                       Name : in String) return String;
   function Get_Issuer (URI : in String) return String;

   function HOTP_SHA1 is
     new Util.Encoders.HMAC.HOTP (Util.Encoders.HMAC.SHA1.HASH_SIZE,
                                  Util.Encoders.HMAC.SHA1.Sign);

   function HOTP_SHA256 is
     new Util.Encoders.HMAC.HOTP (Util.Encoders.HMAC.SHA256.HASH_SIZE,
                                  Util.Encoders.HMAC.SHA256.Sign);

   function To_Positive (Value : in String;
                         Def   : in Positive) return Positive is
     (if Value'Length = 0 then Def else Positive'Value (Value));

   --  otpauth://totp/issuer:account?secret=XXX&issuer=issuer
   function Get_Account (URI : in String) return String is
      Sep : constant Natural := Util.Strings.Index (URI, '?');
   begin
      if Sep = 0 or else URI'Length <= 15 then
         return "";
      end if;
      return URI (URI'First + 15 .. Sep - 1);
   end Get_Account;

   function Get_Param (URI  : in String;
                       Name : in String) return String is
      Sep   : Natural := Util.Strings.Index (URI, '?');
      First : Natural;
   begin
      if Sep = 0 or else URI'Length <= 15 then
         return "";
      end if;
      First := Sep + 1;
      while First < URI'Last loop
         Sep := Util.Strings.Index (URI, '=', First);
         exit when Sep = 0;
         if URI (First .. Sep - 1) = Name then
            First := Sep + 1;
            Sep := Util.Strings.Index (URI, '&', First);
            if Sep = 0 then
               Sep := URI'Last;
            else
               Sep := Sep - 1;
            end if;
            return URI (First .. Sep);
         end if;
         Sep := Util.Strings.Index (URI, '&', Sep + 1);
         exit when Sep = 0;
         First := Sep + 1;
      end loop;
      return "";
   end Get_Param;

   function Get_Issuer (URI : in String) return String is
      Sep    : constant Natural := Util.Strings.Index (URI, '?');
      Issuer : constant String := Get_Param (URI, "issuer");
   begin
      if Sep = 0 or else URI'Length <= 15 then
         return "";
      end if;
      declare
         Sep2 : constant Natural := Util.Strings.Index (URI, ':', URI'First + 15);
      begin
         if Sep2 = 0 or else Sep2 > Sep then
            return "";
         end if;
         if Issuer'Length = 0 then
            return URI (URI'First + 15 .. Sep2 - 1);
         elsif Issuer = URI (URI'First + 15 .. Sep2 - 1) then
            return Issuer;
         else
            return "";
         end if;
      end;
   end Get_Issuer;

   procedure Generate (Account : in String;
                       URI     : in String;
                       Context : in out Context_Type) is

      function Is_Number (S   : in String;
                          Min : in Positive;
                          Max : in Positive) return Boolean is
        (for all I in S'Range => S (I) in '0' .. '9'
         and then Integer'Value (S) in Min .. Max);

      Issuer  : constant String := Get_Issuer (URI);
      Secret  : constant String := Get_Param (URI, "secret");
      Algo    : constant String := Get_Param (URI, "algorithm");
      Digit   : constant String := Get_Param (URI, "digits");
      Period  : constant String := Get_Param (URI, "period");
   begin
      if Secret'Length = 0 then
         AKT.Commands.Log.Error (-("invalid otpauth URI: missing '{0}'"), "secret");
         raise Error;
      end if;
      if Issuer'Length = 0 then
         AKT.Commands.Log.Error (-("invalid otpauth URI: missing '{0}'"), "issuer");
         raise Error;
      end if;
      if Algo'Length /= 0 and then Algo /= "SHA1" and then Algo /= "SHA256" then
         AKT.Commands.Log.Error (-("algorithm '{0}' is not supported"), Algo);
         raise Error;
      end if;
      if Period'Length /= 0 and then not Is_Number (Period, 15, 60) then
         AKT.Commands.Log.Error (-("invalid period '{0}'"), Period);
         raise Error;
      end if;
      if Digit'Length /= 0 and then not Is_Number (Digit, 1, 10) then
         AKT.Commands.Log.Error (-("invalid digits '{0}'"), Digit);
         raise Error;
      end if;

      declare
         P       : constant Positive := To_Positive (Period, 30);
         D       : constant Positive := To_Positive (Digit, 6);
         Now     : constant Ada.Calendar.Time := Ada.Calendar.Clock;
         Time    : constant Interfaces.C.long := Ada.Calendar.Conversions.To_Unix_Time (Now);
         Steps   : constant Interfaces.C.long := Time / Interfaces.C.long (P);
         Decoder : constant Util.Encoders.Decoder := Util.Encoders.Create (Util.Encoders.BASE_32);
         Key     : constant Util.Encoders.Secret_Key := Decoder.Decode_Key (Secret);
         Code    : Natural;
      begin
         if Algo = "SHA1" or else Algo = "" then
            Code := HOTP_SHA1 (Key, Interfaces.Unsigned_64 (Steps), D);
         elsif Algo = "SHA256" then
            Code := HOTP_SHA256 (Key, Interfaces.Unsigned_64 (Steps), D);
         else
            AKT.Commands.Log.Error (-("algorithm not supported '{0}'"), Algo);
            raise Error;
         end if;
         if Account'Length > 0 then
            Context.Console.Notice (N_INFO, Account & ": code:" & Natural'Image (Code));
         else
            Context.Console.Notice (N_INFO, "Code:" & Natural'Image (Code));
         end if;
      end;
   end Generate;

   --  Register or update an otpauth URI.
   --  ------------------------------
   procedure Register (Command : in out Command_Type;
                       URI     : in String;
                       Context : in out Context_Type) is
      Account : constant String := Get_Account (URI);
      Key     : constant String := "otpauth." & Account;
   begin
      Generate ("", URI, Context);

      if Context.Wallet.Contains (Key)
        and then not Confirm (-("override existing otpauth entry ?"))
      then
         return;
      end if;

      Context.Wallet.Set (Name => Key, Content => URI);
   end Register;

   --  ------------------------------
   --  Collect the list of OTP definitions in the keystore.
   --  ------------------------------
   procedure Collect_List (Context : in out Context_Type;
                           Into    : in out Util.Strings.Vectors.Vector) is
      List   : Keystore.Entry_Map;
      Iter   : Keystore.Entry_Cursor;
      Prefix : constant String := "otpauth.";
   begin
      Into.Clear;
      Context.Wallet.List (Content => List);
      Iter := List.First;
      while Keystore.Entry_Maps.Has_Element (Iter) loop
         declare
            Name   : constant String := Keystore.Entry_Maps.Key (Iter);
         begin
            if Util.Strings.Starts_With (Name, Prefix) then
               Into.Append (Name);
            end if;
         end;
         Keystore.Entry_Maps.Next (Iter);
      end loop;
   end Collect_List;

   --  ------------------------------
   --  Generate to OTP code for the selected account.
   --  ------------------------------
   procedure Generate (Command : in out Command_Type;
                       Account : in String;
                       Context : in out Context_Type) is
      Prefix : constant String := "otpauth.";

      function Match (Name : in String) return Boolean is
        (Util.Strings.Starts_With (Name, Prefix & Account & ":")
         or else Util.Strings.Ends_With (Name, ":" & Account));

      Names : Util.Strings.Vectors.Vector;
      Found : Boolean := False;
   begin
      Collect_List (Context, Names);
      for Name of Names loop
         if Match (Name) then
            declare
               URI     : constant String := Context.Wallet.Get (Name);
            begin
               Generate (Get_Account (URI), URI, Context);
               Found := True;
            end;
         end if;
      end loop;
      if not Found then
         AKT.Commands.Log.Error (-("no otpauth matching account '{0}'"), Account);
         raise Error;
      end if;
   end Generate;

   --  ------------------------------
   --  List the OTP authorizations that are registered.
   --  ------------------------------
   procedure List (Command   : in out Command_Type;
                   Context   : in out Context_Type) is
      Names : Util.Strings.Vectors.Vector;
   begin
      Collect_List (Context, Names);
      for Name of Names loop
         declare
            URI : constant String := Context.Wallet.Get (Name);
            Account : constant String := Get_Account (URI);
         begin
            Context.Console.Notice (N_INFO, Account);
         end;
      end loop;
   end List;

   --  ------------------------------
   --  Store the otpauth secret or generate the OTP code.
   --  ------------------------------
   overriding
   procedure Execute (Command   : in out Command_Type;
                      Name      : in String;
                      Args      : in Argument_List'Class;
                      Context   : in out Context_Type) is
   begin
      Context.Open_Keystore (Args, Use_Worker => False);
      if Context.First_Arg > Args.Get_Count  then
         Command.List (Context);

      else
         declare
            URI : constant String := Args.Get_Argument (2);
         begin
            if Util.Strings.Starts_With (URI, "otpauth://totp/") then
               Command.Register (URI, Context);
            elsif Util.Strings.Starts_With (URI, "otpauth://") then
               AKT.Commands.Log.Error (-("only 'totp' otpauth URI is supported"));
               raise Error;
            else
               Command.Generate (URI, Context);
            end if;

         exception
            when Keystore.Not_Found =>
               AKT.Commands.Log.Error (-("value '{0}' not found"), URI);
               raise Error;

         end;
      end if;
   end Execute;

   --  ------------------------------
   --  Setup the command before parsing the arguments and executing it.
   --  ------------------------------
   overriding
   procedure Setup (Command : in out Command_Type;
                    Config  : in out GNAT.Command_Line.Command_Line_Configuration;
                    Context : in out Context_Type) is
      package GC renames GNAT.Command_Line;
   begin
      Drivers.Command_Type (Command).Setup (Config, Context);
      GC.Define_Switch (Config, Command.Remove'Access,
                        "-r", "--remove", -("Remove the otpauth URI"));
      GC.Define_Switch (Config, Command.Force'Access,
                        "-f", "--force", -("Force update of existing otpauth URI"));
   end Setup;

end AKT.Commands.OTP;
