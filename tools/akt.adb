-----------------------------------------------------------------------
--  akt -- Ada Keystore Tool
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
with Util.Properties;
package body AKT is

   --  ------------------------------
   --  Configure the logs.
   --  ------------------------------
   procedure Configure_Logs (Debug   : in Boolean;
                             Verbose : in Boolean) is
      Log_Config  : Util.Properties.Manager;
   begin
      Log_Config.Set ("log4j.rootCategory", "ERROR,console");
      Log_Config.Set ("log4j.appender.console", "Console");
      Log_Config.Set ("log4j.appender.console.level", "ERROR");
      Log_Config.Set ("log4j.appender.console.layout", "message");
      Log_Config.Set ("log4j.appender.console.stderr", "true");
      Log_Config.Set ("log4j.logger.Util", "FATAL");
      Log_Config.Set ("log4j.logger.Util.Events", "ERROR");
      Log_Config.Set ("log4j.logger.Keystore", "ERROR");
      Log_Config.Set ("log4j.logger.AKT", "ERROR");
      if Verbose or Debug then
         Log_Config.Set ("log4j.logger.Util", "WARN");
         Log_Config.Set ("log4j.logger.Util.Processes", "INFO");
         Log_Config.Set ("log4j.logger.AKT", "INFO");
         Log_Config.Set ("log4j.logger.Keystore", "INFO");
         Log_Config.Set ("log4j.rootCategory", "INFO,console,verbose");
         Log_Config.Set ("log4j.appender.verbose", "Console");
         Log_Config.Set ("log4j.appender.verbose.level", "INFO");
         Log_Config.Set ("log4j.appender.verbose.layout", "level-message");
      end if;
      if Debug then
         Log_Config.Set ("log4j.logger.AKT", "DEBUG");
         Log_Config.Set ("log4j.logger.Keystore", "DEBUG");
         Log_Config.Set ("log4j.rootCategory", "DEBUG,console,debug");
         Log_Config.Set ("log4j.appender.debug", "Console");
         Log_Config.Set ("log4j.appender.debug.level", "DEBUG");
         Log_Config.Set ("log4j.appender.debug.layout", "full");
      end if;

      Util.Log.Loggers.Initialize (Log_Config);

   end Configure_Logs;

end AKT;
