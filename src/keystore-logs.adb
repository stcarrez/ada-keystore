-----------------------------------------------------------------------
--  keystore-logs -- Log support for the keystore
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
with Util.Encoders.Base16;
package body Keystore.Logs is

   procedure Dump (Log     : in Util.Log.Loggers.Logger;
                   Content : in Ada.Streams.Stream_Element_Array) is
      use type Ada.Streams.Stream_Element_Offset;

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
   end Dump;

   procedure Error (Log     : in Util.Log.Loggers.Logger;
                    Message : in String;
                    Block   : in IO.Block_Number) is
   begin
      if Log.Get_Level >= Util.Log.ERROR_LEVEL then
         Log.Error (Message, IO.Block_Number'Image (Block));
      end if;
   end Error;

   procedure Warn (Log     : in Util.Log.Loggers.Logger;
                   Message : in String;
                   Block   : in IO.Block_Number) is
   begin
      if Log.Get_Level >= Util.Log.WARN_LEVEL then
         Log.Warn (Message, IO.Block_Number'Image (Block));
      end if;
   end Warn;

   procedure Info (Log     : in Util.Log.Loggers.Logger;
                   Message : in String;
                   Block   : in IO.Block_Number) is
   begin
      if Log.Get_Level >= Util.Log.INFO_LEVEL then
         Log.Info (Message, IO.Block_Number'Image (Block));
      end if;
   end Info;

   procedure Debug (Log     : in Util.Log.Loggers.Logger;
                    Message : in String;
                    Block   : in IO.Block_Number) is
   begin
      if Log.Get_Level >= Util.Log.DEBUG_LEVEL then
         Log.Debug (Message, IO.Block_Number'Image (Block));
      end if;
   end Debug;

end Keystore.Logs;
