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

   procedure Debug (Log     : in Util.Log.Loggers.Logger;
                    Message : in String;
                    Block   : in IO.Storage_Block;
                    Size    : in IO.Block_Index);

end Keystore.Logs;
