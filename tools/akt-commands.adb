-----------------------------------------------------------------------
--  akt-commands -- Ada Keystore Tool commands
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
with System.Multiprocessors;
with Ada.Command_Line;
with Ada.Text_IO;
with Ada.Unchecked_Deallocation;
with Util.Strings;
with Util.Commands.Parsers.GNAT_Parser;
with AKT.Configs;
with AKT.Commands.Drivers;
with AKT.Commands.Set;
with AKT.Commands.Get;
with AKT.Commands.Create;
with AKT.Commands.List;
with AKT.Commands.Remove;
with AKT.Commands.Edit;
with AKT.Commands.Extract;
with AKT.Commands.Store;
with AKT.Commands.Password.Add;
with AKT.Commands.Password.Set;
with AKT.Commands.Password.Remove;
with AKT.Passwords.Input;
with AKT.Passwords.Files;
with AKT.Passwords.Unsafe;
package body AKT.Commands is

   Help_Command            : aliased AKT.Commands.Drivers.Help_Command_Type;
   Set_Command             : aliased AKT.Commands.Set.Command_Type;
   Store_Command           : aliased AKT.Commands.Store.Command_Type;
   Get_Command             : aliased AKT.Commands.Get.Command_Type;
   Extract_Command         : aliased AKT.Commands.Extract.Command_Type;
   Create_Command          : aliased AKT.Commands.Create.Command_Type;
   List_Command            : aliased AKT.Commands.List.Command_Type;
   Remove_Command          : aliased AKT.Commands.Remove.Command_Type;
   Edit_Command            : aliased AKT.Commands.Edit.Command_Type;
   Set_Password_Command    : aliased AKT.Commands.Password.Set.Command_Type;
   Add_Password_Command    : aliased AKT.Commands.Password.Add.Command_Type;
   Remove_Password_Command : aliased AKT.Commands.Password.Remove.Command_Type;

   Driver                  : Drivers.Driver_Type;
   Arguments               : Util.Commands.Dynamic_Argument_List;

   --  ------------------------------
   --  Print the command usage.
   --  ------------------------------
   procedure Usage (Args    : in Argument_List'Class;
                    Context : in out Context_Type;
                    Name    : in String := "") is
   begin
      GC.Display_Help (Context.Command_Config);
      if Name'Length > 0 then
         Driver.Usage (Args, Context, Name);
      end if;
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end Usage;

   procedure Usage (Context : in out Context_Type;
                    Name    : in String := "") is
   begin
      GC.Display_Help (Context.Command_Config);
      if Name'Length > 0 then
         Driver.Usage (Arguments, Context, Name);
      end if;
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end Usage;

   --  ------------------------------
   --  Open the keystore file using the password password.
   --  When `Use_Worker` is set, a workers of N tasks is created and assigned to the keystore
   --  for the decryption and encryption process.
   --  ------------------------------
   procedure Open_Keystore (Context    : in out Context_Type;
                            Use_Worker : in Boolean := False) is
   begin
      Context.Wallet.Open (Password => Context.Provider.Get_Password,
                           Path     => Context.Wallet_File.all);
      if Use_Worker then
         Context.Workers := new Keystore.Task_Manager (Context.Worker_Count);
         Keystore.Start (Context.Workers);
         Context.Wallet.Set_Work_Manager (Context.Workers);
      end if;
   end Open_Keystore;

   --  ------------------------------
   --  Open the keystore file and change the password.
   --  ------------------------------
   procedure Change_Password (Context      : in out Context_Type;
                              New_Password : in Keystore.Secret_Key;
                              Config       : in Keystore.Wallet_Config;
                              Mode         : in Keystore.Mode_Type) is
      Password : constant Keystore.Secret_Key := Context.Provider.Get_Password;
   begin
      Context.Wallet.Open (Password => Password,
                           Path     => Context.Wallet_File.all);
      Context.Wallet.Set_Key (Password     => Password,
                              New_Password => New_Password,
                              Config       => Config,
                              Mode         => Mode);
   end Change_Password;

   --  ------------------------------
   --  Set the password provider to get a password.
   --  ------------------------------
   procedure Set_Password_Provider (Context  : in out Context_Type;
                                    Provider : in AKT.Passwords.Provider_Access) is
   begin
      Context.Provider := Provider;
   end Set_Password_Provider;

   --  ------------------------------
   --  Execute the command with its arguments.
   --  ------------------------------
   procedure Execute (Name    : in String;
                      Args    : in Argument_List'Class;
                      Context : in out Context_Type) is
   begin
      Log.Info ("Execute command {0}", Name);

      Driver.Execute (Name, Args, Context);
   end Execute;

   --  ------------------------------
   --  Initialize the commands.
   --  ------------------------------
   overriding
   procedure Initialize (Context : in out Context_Type) is
   begin
      Context.Worker_Count := Positive (System.Multiprocessors.Number_Of_CPUs);

      GC.Set_Usage (Config => Context.Command_Config,
                    Usage  => "[switchs] command [arguments]",
                    Help   => "akt - tool to store and protect your sensitive data");
      GC.Define_Switch (Config => Context.Command_Config,
                        Output => Context.Version'Access,
                        Switch => "-v",
                        Long_Switch => "--version",
                        Help   => "Print the version");
      GC.Define_Switch (Config => Context.Command_Config,
                        Output => Context.Debug'Access,
                        Switch => "-d",
                        Long_Switch => "--debug",
                        Help   => "Enable debug execution");
      GC.Define_Switch (Config => Context.Command_Config,
                        Output => Context.Debug'Access,
                        Switch => "-z",
                        Long_Switch => "--zero",
                        Help   => "Erase and fill with zeros instead of random values");
      GC.Define_Switch (Config => Context.Command_Config,
                        Output => Context.Wallet_File'Access,
                        Switch => "-f:",
                        Long_Switch => "--file=",
                        Argument => "PATH",
                        Help   => "Defines the path for the wallet file");
      GC.Define_Switch (Config => Context.Command_Config,
                        Output => Context.Password_File'Access,
                        Long_Switch => "--passfile=",
                        Argument => "PATH",
                        Help   => "Read the file that contains the password");
      GC.Define_Switch (Config => Context.Command_Config,
                        Output => Context.Unsafe_Password'Access,
                        Long_Switch => "--passfd=",
                        Argument => "NUM",
                        Help   => "Read the password from the pipe with"
                          & " the given file descriptor");
      GC.Define_Switch (Config => Context.Command_Config,
                        Output => Context.Unsafe_Password'Access,
                        Long_Switch => "--passsocket=",
                        Help   => "The password is passed within the socket connection");
      GC.Define_Switch (Config => Context.Command_Config,
                        Output => Context.Password_Env'Access,
                        Long_Switch => "--passenv=",
                        Argument => "NAME",
                        Help   => "Read the environment variable that contains"
                        & " the password (not safe)");
      GC.Define_Switch (Config => Context.Command_Config,
                        Output => Context.Unsafe_Password'Access,
                        Switch => "-p:",
                        Long_Switch => "--password=",
                        Help   => "The password is passed within the command line (not safe)");
      GC.Define_Switch (Config => Context.Command_Config,
                        Output => Context.Worker_Count'Access,
                        Switch => "-t:",
                        Long_Switch => "--thread=",
                        Initial  => Context.Worker_Count,
                        Argument => "COUNT",
                        Help   => "Number of threads for the encryption/decryption process");
      GC.Initialize_Option_Scan (Stop_At_First_Non_Switch => True);

      Driver.Set_Description ("akt - tool to store and protect your sensitive data");
      Driver.Set_Usage ("[-v] [-d] [-f keystore] [-p <password>] <command> [<args>]" & ASCII.LF &
                          "where:" & ASCII.LF &
                          "  -v           Print the tool version" & ASCII.LF &
                          "  -d           Debug execution mode" & ASCII.LF &
                          "  -f keystore  The keystore file to use");
      Driver.Add_Command ("help", "print some help", Help_Command'Access);
      Driver.Add_Command ("set", "insert or update a value in the keystore", Set_Command'Access);
      Driver.Add_Command ("store", "read the standard input and insert or update the"
                          & " content in the keystore", Store_Command'Access);
      Driver.Add_Command ("get", "get a value from the keystore", Get_Command'Access);
      Driver.Add_Command ("extract", "get a value from the keystore", Extract_Command'Access);
      Driver.Add_Command ("create", "create the keystore", Create_Command'Access);
      Driver.Add_Command ("list", "list values of the keystore", List_Command'Access);
      Driver.Add_Command ("remove", "remove values from the keystore", Remove_Command'Access);
      Driver.Add_Command ("edit", "edit the value with an external editor", Edit_Command'Access);
      Driver.Add_Command ("password-set", "change the password", Set_Password_Command'Access);
      Driver.Add_Command ("password-add", "add a password", Add_Password_Command'Access);
      Driver.Add_Command ("password-remove", "remove a password", Remove_Password_Command'Access);
   end Initialize;

   procedure Parse (Context   : in out Context_Type;
                    Arguments : out Util.Commands.Dynamic_Argument_List) is
   begin
      GC.Getopt (Config => Context.Command_Config);
      Util.Commands.Parsers.GNAT_Parser.Get_Arguments (Arguments, GC.Get_Argument);

      if Context.Debug then
         AKT.Configure_Logs (Debug => Context.Debug, Verbose => Context.Debug);
      end if;

      if Context.Version then
         Ada.Text_IO.Put_Line (AKT.Configs.RELEASE);
         return;
      end if;

      if Context.Password_File'Length > 0 then
         Context.Provider := Passwords.Files.Create (Context.Password_File.all);
      elsif Context.Unsafe_Password'Length > 0 then
         Context.Provider := Passwords.Unsafe.Create (Context.Unsafe_Password.all);
      else
         Context.Provider := AKT.Passwords.Input.Create (False);
      end if;

      declare
         Cmd_Name : constant String := Arguments.Get_Command_Name;
      begin
         if Cmd_Name'Length = 0 then
            Ada.Text_IO.Put_Line ("Missing command name to execute.");
            AKT.Commands.Usage (Arguments, Context);
            Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
            return;
         end if;
         AKT.Commands.Execute (Cmd_Name, Arguments, Context);
      end;

   end Parse;

   procedure Parse_Range (Value  : in String;
                          Config : in out Keystore.Wallet_Config) is
      Pos  : constant Natural := Util.Strings.Index (Value, ':');
      Low  : Integer := Config.Min_Counter;
      High : Integer := Config.Max_Counter;
   begin
      if Pos > 0 then
         Low  := Integer'Value (Value (Value'First .. Pos - 1));
         High := Integer'Value (Value (Pos + 1 .. Value'Last));
      else
         High := Integer'Value (Value);
         if Low > High then
            Low := High;
         end if;
      end if;
      if not (Low in Positive'Range) or not (High in Positive'Range) then
         AKT.Commands.Log.Error ("Value is out of range");
         raise Error;
      end if;
      if Low > High then
         AKT.Commands.Log.Error ("The min counter is greater than max counter");
         raise Error;
      end if;
      Config.Min_Counter := Positive (Low);
      Config.Max_Counter := Positive (High);

   exception
      when Error =>
         raise;

      when others =>
         AKT.Commands.Log.Error ("Invalid counter range: " & Value);
         AKT.Commands.Log.Error ("Valid format are 'MAX_COUNTER' or 'MIN_COUNTER:MAX_COUNTER'");
         AKT.Commands.Log.Error ("Counters must be positive integers.");
         raise Error;

   end Parse_Range;

   overriding
   procedure Finalize (Context : in out Context_Type) is
      use type Keystore.Task_Manager_Access;
      procedure Free is
        new Ada.Unchecked_Deallocation (Object => AKT.Passwords.Provider'Class,
                                        Name   => AKT.Passwords.Provider_Access);
      procedure Free is
        new Ada.Unchecked_Deallocation (Object => Keystore.Task_Manager,
                                        Name   => Keystore.Task_Manager_Access);
   begin
      if Context.Workers /= null then
         Keystore.Stop (Context.Workers);
         Free (Context.Workers);
      end if;
      GC.Free (Context.Command_Config);
      Free (Context.Provider);
   end Finalize;

end AKT.Commands;
