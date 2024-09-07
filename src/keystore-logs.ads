-----------------------------------------------------------------------
--  keystore-logs -- Log support for the keystore
--  Copyright (C) 2019, 2020 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with Util.Log.Loggers;
with Keystore.IO;
private package Keystore.Logs is

   procedure Dump (Log     : in Util.Log.Loggers.Logger;
                   Content : in Ada.Streams.Stream_Element_Array);

   procedure Error (Log     : in Util.Log.Loggers.Logger;
                    Message : in String;
                    Block   : in IO.Storage_Block);

   procedure Warn (Log     : in Util.Log.Loggers.Logger;
                   Message : in String;
                   Block   : in IO.Storage_Block);

   procedure Info (Log     : in Util.Log.Loggers.Logger;
                   Message : in String;
                   Block   : in IO.Storage_Block);

   procedure Debug (Log     : in Util.Log.Loggers.Logger;
                    Message : in String;
                    Block   : in IO.Storage_Block);

   procedure Debug (Log     : in Util.Log.Loggers.Logger;
                    Message : in String;
                    Block1  : in IO.Storage_Block;
                    Block2  : in IO.Storage_Block);

end Keystore.Logs;
