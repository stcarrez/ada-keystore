-----------------------------------------------------------------------
--  akt -- Ada Keystore Tool
--  Copyright (C) 2019, 2021 Stephane Carrez
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

with Ada.Text_IO;
with Ada.Finalization;
with Ada.Calendar;
with Util.Strings.Builders;
with Util.Log.Loggers;
with Util.Log.Appenders;
with Util.Log.Appenders.Factories;
with Util.Log.Appenders.Formatter;
with Util.Properties;
package body AKT is

   --  ------------------------------
   --  Console appender
   --  ------------------------------
   --  Write log events to the console
   type Console_Appender is new Util.Log.Appenders.Appender with null record;
   type Console_Appender_Access is access all Console_Appender'Class;

   overriding
   procedure Append (Self  : in out Console_Appender;
                     Message : in Util.Strings.Builders.Builder;
                     Date    : in Ada.Calendar.Time;
                     Level   : in Util.Log.Level_Type;
                     Logger  : in String);

   --  Flush the log events.
   overriding
   procedure Flush (Self   : in out Console_Appender);

   --  Create a console appender and configure it according to the properties
   function Create_Console_Appender (Name       : in String;
                                     Properties : in Util.Properties.Manager;
                                     Default    : in Util.Log.Level_Type)
                                     return Util.Log.Appenders.Appender_Access;

   overriding
   procedure Append (Self    : in out Console_Appender;
                     Message : in Util.Strings.Builders.Builder;
                     Date    : in Ada.Calendar.Time;
                     Level   : in Util.Log.Level_Type;
                     Logger  : in String) is
      procedure Write_Standard_Error (Data : in String) with Inline_Always;

      procedure Write_Standard_Error (Data : in String) is
      begin
         Ada.Text_IO.Put (Ada.Text_IO.Current_Error, Data);
      end Write_Standard_Error;

      procedure Write_Error is new Util.Log.Appenders.Formatter (Write_Standard_Error);
   begin
      if Self.Level >= Level then
         Ada.Text_IO.Put (Ada.Text_IO.Current_Error, "akt: ");
         Write_Error (Self, Message, Date, Level, Logger);
         Ada.Text_IO.New_Line (Ada.Text_IO.Current_Error);
      end if;
   end Append;

   --  ------------------------------
   --  Flush the log events.
   --  ------------------------------
   overriding
   procedure Flush (Self : in out Console_Appender) is
      pragma Unreferenced (Self);
   begin
      Ada.Text_IO.Flush (Ada.Text_IO.Standard_Error);
   end Flush;

   --  ------------------------------
   --  Create a console appender and configure it according to the properties
   --  ------------------------------
   function Create_Console_Appender (Name       : in String;
                                     Properties : in Util.Properties.Manager;
                                     Default    : in Util.Log.Level_Type)
                                    return Util.Log.Appenders.Appender_Access is
      pragma Unreferenced (Properties, Default);

      Result : constant Console_Appender_Access
        := new Console_Appender '(Ada.Finalization.Limited_Controlled with Length => Name'Length,
                                  Name => Name,
                                  others => <>);
   begin
      Result.Set_Level (Util.Log.ERROR_LEVEL);
      Result.Set_Layout (Util.Log.Appenders.MESSAGE);
      return Result.all'Access;
   end Create_Console_Appender;

   package Console_Factory is
      new Util.Log.Appenders.Factories (Name   => "aktConsole",
                                        Create => Create_Console_Appender'Access);

   --  ------------------------------
   --  Configure the logs.
   --  ------------------------------
   procedure Configure_Logs (Debug   : in Boolean;
                             Dump    : in Boolean;
                             Verbose : in Boolean) is
      Log_Config  : Util.Properties.Manager;
   begin
      Log_Config.Set ("log4j.rootCategory", "ERROR,errorConsole");
      Log_Config.Set ("log4j.appender.errorConsole", "aktConsole");
      Log_Config.Set ("log4j.appender.errorConsole.level", "ERROR");
      Log_Config.Set ("log4j.appender.errorConsole.layout", "message");
      Log_Config.Set ("log4j.appender.errorConsole.stderr", "true");
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

begin
   Console_Factory.Register;
end AKT;
