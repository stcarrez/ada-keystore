-----------------------------------------------------------------------
--  keystore-files -- Ada keystore files
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
with Ada.Unchecked_Deallocation;
with Util.Encoders.AES;
with Util.Log.Loggers;
with Keystore.Keys;
package body Keystore.Files is

   procedure Free is
     new Ada.Unchecked_Deallocation (Object => IO.Files.Wallet_File_Stream,
                                     Name   => Wallet_File_Stream_Access);

   Header_Key : constant Secret_Key
     := Util.Encoders.Create ("If you can't give me poetry, can't you give me poetical science?");

   Log : constant Util.Log.Loggers.Logger := Util.Log.Loggers.Create ("Keystore.Keys");

   --  ------------------------------
   --  Open the keystore file using the given password.
   --  Raises the Bad_Password exception if no key slot match the password.
   --  ------------------------------
   procedure Open (Container : in out Wallet_File;
                   Password  : in Secret_Key;
                   Path      : in String) is
      Master : Keystore.Keys.Key_Manager;
   begin
      Log.Debug ("Open keystore {0}", Path);

      Container.Stream := new IO.Files.Wallet_File_Stream;
      Container.Stream.Open (Path);
      Master.Set_Header_Key (Header_Key);
      Container.Repository.Open (Password, 1, 1, Master, Container.Stream.all);
      Container.Container.Set_Stream (Container.Stream);
      Log.Info ("Keystore {0} is opened", Path);

   exception
      when others =>
         if Container.Stream /= null then
            Container.Stream.Close;
         end if;
         Free (Container.Stream);
         raise;
   end Open;

   --  ------------------------------
   --  Create the keystore file and protect it with the given password.
   --  The key slot #1 is used.
   --  ------------------------------
   procedure Create (Container : in out Wallet_File;
                     Password  : in Secret_Key;
                     Path      : in String) is
      Master : Keystore.Keys.Key_Manager;
      Block  : IO.Block_Number;
   begin
      Log.Debug ("Create keystore {0}", Path);

      Container.Stream := new IO.Files.Wallet_File_Stream;
      Container.Stream.Create (Path);
      Container.Container.Set_Stream (Container.Stream);
      Master.Set_Header_Key (Header_Key);
      Container.Stream.Allocate (Block);
      Container.Repository.Create (Password, Block, 1, Master, Container.Stream.all);
   end Create;

   --  Add in the wallet the named entry and associate it the children wallet.
   --  The children wallet meta data is protected by the container.
   --  The children wallet has its own key to protect the named entries it manages.
   procedure Add (Container : in out Wallet_File;
                  Name      : in String;
                  Wallet    : in out Wallet_File'Class) is
   begin
      null;
   end Add;

   --  Load from the container the named children wallet.
   procedure Load (Container : in out Wallet_File;
                   Name      : in String;
                   Wallet    : in out Wallet_File'Class) is
   begin
      null;
   end Load;

   overriding
   procedure Initialize (Wallet : in out Wallet_File) is
   begin
      Wallet.Container.Set_Repository (Wallet.Repository'Unchecked_Access);
   end Initialize;

   overriding
   procedure Finalize (Wallet : in out Wallet_File) is
   begin
      if Wallet.Stream /= null then
         Wallet.Stream.Close;
      end if;
      Free (Wallet.Stream);
   end Finalize;

end Keystore.Files;
