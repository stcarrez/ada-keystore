-----------------------------------------------------------------------
--  keystore-logs -- Log support for the keystore
--  Copyright (C) 2019, 2020 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with Util.Encoders.Base16;
with Keystore.Buffers;
package body Keystore.Logs is

   procedure Dump (Log     : in Util.Log.Loggers.Logger;
                   Content : in Ada.Streams.Stream_Element_Array) is
      use type Ada.Streams.Stream_Element_Offset;
   begin
      if Log.Get_Level >= Util.Log.DEBUG_LEVEL then
         declare
            Encoder : Util.Encoders.Base16.Encoder;
            Start   : Ada.Streams.Stream_Element_Offset := Content'First;
            Last    : Ada.Streams.Stream_Element_Offset;
         begin
            while Start <= Content'Last loop
               Last := Start + 31;
               if Last > Content'Last then
                  Last := Content'Last;
               end if;
               Log.Debug (" {0}", Encoder.Transform (Content (Start .. Last)));
               Start := Last + 1;
            end loop;
         end;
      end if;
   end Dump;

   procedure Error (Log     : in Util.Log.Loggers.Logger;
                    Message : in String;
                    Block   : in IO.Storage_Block) is
   begin
      if Log.Get_Level >= Util.Log.ERROR_LEVEL then
         Log.Error (Message, Buffers.To_String (Block));
      end if;
   end Error;

   procedure Warn (Log     : in Util.Log.Loggers.Logger;
                   Message : in String;
                   Block   : in IO.Storage_Block) is
   begin
      if Log.Get_Level >= Util.Log.WARN_LEVEL then
         Log.Warn (Message, Buffers.To_String (Block));
      end if;
   end Warn;

   procedure Info (Log     : in Util.Log.Loggers.Logger;
                   Message : in String;
                   Block   : in IO.Storage_Block) is
   begin
      if Log.Get_Level >= Util.Log.INFO_LEVEL then
         Log.Info (Message, Buffers.To_String (Block));
      end if;
   end Info;

   procedure Debug (Log     : in Util.Log.Loggers.Logger;
                    Message : in String;
                    Block   : in IO.Storage_Block) is
   begin
      if Log.Get_Level >= Util.Log.DEBUG_LEVEL then
         Log.Debug (Message, Buffers.To_String (Block));
      end if;
   end Debug;

   procedure Debug (Log     : in Util.Log.Loggers.Logger;
                    Message : in String;
                    Block1  : in IO.Storage_Block;
                    Block2  : in IO.Storage_Block) is
   begin
      if Log.Get_Level >= Util.Log.DEBUG_LEVEL then
         Log.Debug (Message, Buffers.To_String (Block1), Buffers.To_String (Block2));
      end if;
   end Debug;

end Keystore.Logs;
