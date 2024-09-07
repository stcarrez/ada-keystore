-----------------------------------------------------------------------
--  akt-filesystem -- Fuse filesystem operations
--  Copyright (C) 2019, 2020 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with Ada.Streams;
with Fuse.Main;
with Keystore.Files;
package AKT.Filesystem is

   type User_Data_Type is record
      Wallet     : access Keystore.Files.Wallet_File;
      Direct_IO  : Boolean := False;
   end record;

   pragma Warnings (Off, "* bits of * unused");

   type Stream_Element_Array is array (Positive range <>) of Ada.Streams.Stream_Element;

   package Fuse_Keystore is
     new Fuse.Main (Element_Type   => Ada.Streams.Stream_Element,
                    Element_Array  => Stream_Element_Array,
                    User_Data_Type => User_Data_Type);

   pragma Warnings (On, "* bits of * unused");

private

   use Fuse_Keystore;

   function GetAttr (Path   : in String;
                     St_Buf : access System.Stat_Type)
                     return System.Error_Type;

   function MkDir (Path   : in String;
                   Mode   : in System.St_Mode_Type)
                   return System.Error_Type;

   function Unlink (Path   : in String)
                    return System.Error_Type;

   function RmDir (Path   : in String)
                   return System.Error_Type;

   function Create (Path   : in String;
                    Mode   : in System.St_Mode_Type;
                    Fi     : access System.File_Info_Type)
                    return System.Error_Type;

   function Open (Path   : in String;
                  Fi     : access System.File_Info_Type)
                  return System.Error_Type;

   function Release (Path   : in String;
                     Fi     : access System.File_Info_Type)
                     return System.Error_Type;

   function Read (Path   : in String;
                  Buffer : access Buffer_Type;
                  Size   : in out Natural;
                  Offset : in Natural;
                  Fi     : access System.File_Info_Type)
                  return System.Error_Type;

   function Write (Path   : in String;
                   Buffer : access Buffer_Type;
                   Size   : in out Natural;
                   Offset : in Natural;
                   Fi     : access System.File_Info_Type)
                   return System.Error_Type;

   function ReadDir (Path   : in String;
                     Filler : access procedure
                       (Name     : String;
                        St_Buf   : System.Stat_Access;
                        Offset   : Natural);
                     Offset : in Natural;
                     Fi     : access System.File_Info_Type)
                     return System.Error_Type;

   function Truncate (Path   : in String;
                      Size   : in Natural)
                      return System.Error_Type;

   package Keystore_Truncate is new Fuse_Keystore.Truncate;
   package Keystore_GetAttr is new Fuse_Keystore.GetAttr;
   package Keystore_MkDir is new Fuse_Keystore.MkDir;
   package Keystore_Unlink is new Fuse_Keystore.Unlink;
   package Keystore_RmDir is new Fuse_Keystore.RmDir;
   package Keystore_Create is new Fuse_Keystore.Create;
   package Keystore_Open is new Fuse_Keystore.Open;
   package Keystore_Release is new Fuse_Keystore.Release;
   package Keystore_Read is new Fuse_Keystore.Read;
   package Keystore_Write is new Fuse_Keystore.Write;
   package Keystore_ReadDir is new Fuse_Keystore.ReadDir;

end AKT.Filesystem;
