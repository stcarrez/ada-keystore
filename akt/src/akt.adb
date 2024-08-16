-----------------------------------------------------------------------
--  akt -- Ada Keystore Tool
--  Copyright (C) 2019, 2021, 2023 Stephane Carrez
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
with Util.Properties;
package body AKT is

   --  ------------------------------
   --  Configure the logs.
   --  ------------------------------
   procedure Configure_Logs (Debug   : in Boolean;
                             Dump    : in Boolean;
                             Verbose : in Boolean) is
      Log_Config  : Util.Properties.Manager;
   begin
      Log_Config.Set ("log4j.rootCategory", "ERROR,errorConsole");
      Log_Config.Set ("log4j.appender.errorConsole", "Console");
      Log_Config.Set ("log4j.appender.errorConsole.level", "ERROR");
      Log_Config.Set ("log4j.appender.errorConsole.layout", "message");
      Log_Config.Set ("log4j.appender.errorConsole.stderr", "true");
      Log_Config.Set ("log4j.appender.errorConsole.prefix", "akt: ");
      Log_Config.Set ("log4j.appender.errorConsole.utf8", "true");
      Log_Config.Set ("log4j.logger.Util", "FATAL");
      Log_Config.Set ("log4j.logger.Util.Events", "ERROR");
      Log_Config.Set ("log4j.logger.Keystore", "ERROR");
      Log_Config.Set ("log4j.logger.AKT", "ERROR");
      if Verbose or Debug or Dump then
         Log_Config.Set ("log4j.logger.Util", "WARN");
         Log_Config.Set ("log4j.logger.AKT", "INFO");
         Log_Config.Set ("log4j.logger.Keystore.IO", "WARN");
         Log_Config.Set ("log4j.logger.Keystore", "INFO");
         Log_Config.Set ("log4j.rootCategory", "INFO,errorConsole,verbose");
         Log_Config.Set ("log4j.appender.verbose", "Console");
         Log_Config.Set ("log4j.appender.verbose.level", "INFO");
         Log_Config.Set ("log4j.appender.verbose.layout", "level-message");
      end if;
      if Debug or Dump then
         Log_Config.Set ("log4j.logger.Util.Processes", "INFO");
         Log_Config.Set ("log4j.logger.AKT", "DEBUG");
         Log_Config.Set ("log4j.logger.Keystore.IO", "INFO");
         Log_Config.Set ("log4j.logger.Keystore", "DEBUG");
         Log_Config.Set ("log4j.rootCategory", "DEBUG,errorConsole,debug");
         Log_Config.Set ("log4j.appender.debug", "Console");
         Log_Config.Set ("log4j.appender.debug.level", "DEBUG");
         Log_Config.Set ("log4j.appender.debug.layout", "full");
      end if;
      if Dump then
         Log_Config.Set ("log4j.logger.Keystore.IO", "DEBUG");
      end if;

      Util.Log.Loggers.Initialize (Log_Config);

   end Configure_Logs;

end AKT;
