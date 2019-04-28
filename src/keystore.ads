-----------------------------------------------------------------------
--  keystore -- Ada keystore
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
with Util.Encoders;
with Ada.Streams;
with Ada.Calendar;
with Ada.Strings.Hash;
with Ada.Containers.Indefinite_Hashed_Maps;
private with Ada.Finalization;
limited private with Keystore.IO;
limited private with Keystore.Metadata;

--  == Keystore ==
--  The `Keystore` package provides operations to store information in secure wallets and
--  protect the stored information by encrypting the content.  It is necessary to know one
--  of the wallet password to access its content.  Wallets are protected by a master key
--  using AES-256 and the wallet master key is protected by a user password.  The wallet
--  defines up to 8 slots that identify a password key that is able to unlock the master key.
--  To open a wallet, it is necessary to unlock one of the 8 slots by providing the correct
--  password.  Wallet key slots are protected by the user's password and the PBKDF2-HMAC-256
--  algorithm, a random salt, a random counter and they are encrypted using AES-256.
--
--  === Creation ===
--  To create a keystore you will first declare a `Wallet_File` instance.  You will also need
--  a password that will be used to protect the wallet master key.
--
--    with Keystore.Files;
--    ...
--      WS   : Keystore.Files.Wallet_File;
--      Pass : Keystore.Secret := Keystore.Create ("There was no choice but to be pioneers");
--
--  You can then create the keystore file by using the `Create` operation:
--
--      WS.Create ("secure.akt", Pass);
--
--  === Storing ===
--  Values stored in the wallet are protected by their own encryption keys using AES-256.
--  The encryption key is generated when the value is added to the wallet by using the `Add`
--  operation.
--
--      WS.Add ("Grace Hopper", "If it's a good idea, go ahead and do it.");
--
--  The `Get` function allows to retrieve the value.  The value is decrypted only when the `Get`
--  operation is called.
--
--      Citation : constant String := WS.Get ("Grace Hopper");
--
--  The `Delete` procedure can be used to remove the value.  When the value is removed,
--  the encryption key and the data are erased.
--
--      WS.Delete ("Grace Hopper");
--
package Keystore is

   subtype Secret_Key is Util.Encoders.Secret_Key;

   function Create (Password : in String) return Secret_Key
     renames Util.Encoders.Create;

   --  Exception raised when a keystore entry was not found.
   Not_Found     : exception;

   --  Exception raised when a keystore entry already exist.
   Name_Exist    : exception;

   --  Exception raised when the wallet cannot be opened with the given password.
   Bad_Password  : exception;

   --  Exception raised when the wallet is corrupted.
   Corrupted     : exception;

   --  Invalid data block when reading the wallet.
   Invalid_Block : exception;

   --  The wallet state.
   type State_Type is (S_INVALID, S_CONFIGURED, S_OPEN, S_CLOSED);

   --  Identifies the type of data stored for a named entry in the wallet.
   type Entry_Type is (T_INVALID, T_STRING, T_BINARY, T_WALLET);

   --  Information about a keystore entry.
   type Entry_Info is record
      Size        : Natural := 0;
      Kind        : Entry_Type := T_INVALID;
      Create_Date : Ada.Calendar.Time;
      Update_Date : Ada.Calendar.Time;
   end record;

   package Entry_Maps is
     new Ada.Containers.Indefinite_Hashed_Maps (Key_Type        => String,
                                                Element_Type    => Entry_Info,
                                                Hash            => Ada.Strings.Hash,
                                                Equivalent_Keys => "=",
                                                "="             => "=");

   subtype Entry_Map is Entry_Maps.Map;
   subtype Entry_Cursor is Entry_Maps.Cursor;

   --  Defines the key slot number.
   type Key_Slot is new Positive range 1 .. 8;

   type Wallet is tagged limited private;

   --  Return True if the container was configured.
   function Is_Configured (Container : in Wallet) return Boolean;

   --  Return True if the container can be accessed.
   function Is_Open (Container : in Wallet) return Boolean;

   --  Get the wallet state.
   function State (Container : in Wallet) return State_Type;

   --  Set the key to encrypt and decrypt the container meta data.
   procedure Set_Key (Container : in out Wallet;
                      Secret    : in Secret_Key) with
     Pre => Container.State /= S_OPEN;

   --  Return True if the container contains the given named entry.
   function Contains (Container : in Wallet;
                      Name      : in String) return Boolean with
     Pre => Container.Is_Open;

   --  Add in the wallet the named entry and associate it the content.
   --  The content is encrypted in AES-CBC with a secret key and an IV vector
   --  that is created randomly for the new named entry.
   procedure Add (Container : in out Wallet;
                  Name      : in String;
                  Content   : in String) with
     Pre  => Container.Is_Open,
     Post => Container.Contains (Name);

   --  Add in the wallet the named entry and associate it the content.
   --  The content is encrypted in AES-CBC with a secret key and an IV vector
   --  that is created randomly for the new named entry.
   procedure Add (Container : in out Wallet;
                  Name      : in String;
                  Content   : in Ada.Streams.Stream_Element_Array) with
     Pre  => Container.Is_Open,
     Post => Container.Contains (Name);

   --  Add or update in the wallet the named entry and associate it the content.
   --  The content is encrypted in AES-CBC with a secret key and an IV vector
   --  that is created randomly for the new or updated named entry.
   procedure Set (Container : in out Wallet;
                  Name      : in String;
                  Kind      : in Entry_Type := T_BINARY;
                  Content   : in Ada.Streams.Stream_Element_Array) with
     Pre  => Container.Is_Open,
     Post => Container.Contains (Name);

   --  Add or update in the wallet the named entry and associate it the content.
   --  The content is encrypted in AES-CBC with a secret key and an IV vector
   --  that is created randomly for the new or updated named entry.
   procedure Set (Container : in out Wallet;
                  Name      : in String;
                  Content   : in String) with
     Pre  => Container.Is_Open,
     Post => Container.Contains (Name);

   --  Update in the wallet the named entry and associate it the new content.
   --  The secret key and IV vectors are not changed.
   procedure Update (Container : in out Wallet;
                     Name      : in String;
                     Content   : in String) with
     Pre  => Container.Is_Open,
     Post => Container.Contains (Name);

   --  Delete from the wallet the named entry.
   procedure Delete (Container : in out Wallet;
                     Name      : in String) with
     Pre  => Container.Is_Open,
     Post => not Container.Contains (Name);

   --  Get from the wallet the named entry.
   function Get (Container : in out Wallet;
                 Name      : in String) return String with
     Pre => Container.Is_Open and Container.Contains (Name);

   --  Get the list of entries contained in the wallet.
   procedure List (Container : in out Wallet;
                   Content   : out Entry_Map) with
     Pre => Container.Is_Open;

private

   type Wallet_Identifier is new Positive;

   --  The `Wallet_Container` protects concurrent accesses to the repository.
   protected type Wallet_Container is

      function Get_State return State_Type;

      procedure Set_Key (Secret : in Secret_Key);

      procedure Set_Repository (R : access Keystore.Metadata.Wallet_Repository);

      procedure Set_Stream (S : access Keystore.IO.Wallet_Stream'Class);

      function Contains (Name : in String) return Boolean;

      procedure Add (Name    : in String;
                     Kind    : in Entry_Type;
                     Content : in Ada.Streams.Stream_Element_Array);

      procedure Set (Name    : in String;
                     Kind    : in Entry_Type;
                     Content : in Ada.Streams.Stream_Element_Array);

      procedure Update (Name    : in String;
                        Kind    : in Entry_Type;
                        Content : in Ada.Streams.Stream_Element_Array);

      procedure Get_Data (Name       : in String;
                          Result     : out Entry_Info;
                          Output     : out Ada.Streams.Stream_Element_Array);

      procedure Delete (Name : in String);

      procedure List (Content : out Entry_Map);

      procedure Close;

   private
      Repository : access Keystore.Metadata.Wallet_Repository;
      Stream     : access Keystore.IO.Wallet_Stream'Class;
      State      : State_Type := S_INVALID;
   end Wallet_Container;

   type Wallet is limited new Ada.Finalization.Limited_Controlled with record
      Container : Wallet_Container;
   end record;

end Keystore;
