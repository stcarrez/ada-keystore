-----------------------------------------------------------------------
--  keystore-io-headers -- Keystore file header operations
--  Copyright (C) 2019 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------

with Util.Encoders.SHA256;
with Keystore.Buffers;
package Keystore.IO.Headers is

   type Wallet_Storage is record
      Identifier : Storage_Identifier;
      Pos        : Block_Index;
      Kind       : Interfaces.Unsigned_16;
      Readonly   : Boolean := False;
      Sealed     : Boolean := False;
      Max_Block  : Natural := 0;
      HMAC       : Util.Encoders.SHA256.Hash_Array;
   end record;

   type Wallet_Header is limited record
      UUID            : UUID_Type;
      Identifier      : Storage_Identifier;
      Version         : Natural := 0;
      Block_Size      : Natural := 0;
      Data_Count      : Keystore.Header_Slot_Count_Type := 0;
      Header_Last_Pos : Block_Index;
      Storage_Count   : Natural := 0;
      HMAC            : Util.Encoders.SHA256.Hash_Array;
      Buffer          : Keystore.Buffers.Storage_Buffer;
   end record;

   --  Build a new header with the given UUID and for the storage.
   --  The header buffer is allocated and filled so that it can be written by Write_Header.
   procedure Build_Header (UUID    : in UUID_Type;
                           Storage : in Storage_Identifier;
                           Header  : in out Wallet_Header);

   --  Read the header block and verify its integrity.
   procedure Read_Header (Header  : in out Wallet_Header);

   --  Scan the header block for the storage and call the Process procedure for each
   --  storage information found in the header block.
   procedure Scan_Storage (Header  : in out Wallet_Header;
                           Process : not null access procedure (Storage : in Wallet_Storage));

   --  Sign the header block for the storage.
   procedure Sign_Header (Header  : in out Wallet_Header;
                          Sign    : in Secret_Key);

   --  Set some header data in the keystore file.
   procedure Set_Header_Data (Header : in out Wallet_Header;
                              Index  : in Header_Slot_Index_Type;
                              Kind   : in Header_Slot_Type;
                              Data   : in Ada.Streams.Stream_Element_Array);

   --  Get the header data information from the keystore file.
   procedure Get_Header_Data (Header : in out Wallet_Header;
                              Index  : in Header_Slot_Index_Type;
                              Kind   : out Header_Slot_Type;
                              Data   : out Ada.Streams.Stream_Element_Array;
                              Last   : out Ada.Streams.Stream_Element_Offset);

   --  Add a new storage reference in the header and return its position in the header.
   --  Raises the No_Header_Slot if there is no room in the header.
   procedure Add_Storage (Header     : in out Wallet_Header;
                          Identifier : in Storage_Identifier;
                          Max_Block  : in Positive;
                          Pos        : out Block_Index);

end Keystore.IO.Headers;
