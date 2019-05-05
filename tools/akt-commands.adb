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
with Util.Log.Loggers;
with Util.Commands.Parsers.GNAT_Parser;
with AKT.Commands.Drivers;
with AKT.Commands.Set;
with AKT.Commands.Get;
with AKT.Commands.Create;
with AKT.Commands.List;
with AKT.Commands.Remove;
with AKT.Commands.Edit;
with AKT.Passwords.Input;
with AKT.Passwords.Files;
with AKT.Passwords.Unsafe;
package body AKT.Commands is

   Help_Command     : aliased AKT.Commands.Drivers.Help_Command_Type;
   Set_Command      : aliased AKT.Commands.Set.Command_Type;
   Get_Command      : aliased AKT.Commands.Get.Command_Type;
   Create_Command   : aliased AKT.Commands.Create.Command_Type;
   List_Command     : aliased AKT.Commands.List.Command_Type;
   Remove_Command   : aliased AKT.Commands.Remove.Command_Type;
   Edit_Command     : aliased AKT.Commands.Edit.Command_Type;

   Driver           : Drivers.Driver_Type;
   Arguments        : Util.Commands.Dynamic_Argument_List;

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
   end Usage;

   procedure Usage (Context : in out Context_Type;
                    Name    : in String := "") is
   begin
      GC.Display_Help (Context.Command_Config);
      if Name'Length > 0 then
         Driver.Usage (Arguments, Context, Name);
      end if;
   end Usage;

   --  ------------------------------
   --  Set the keystore path.
   --  ------------------------------
   procedure Set_Keystore_Path (Context : in out Context_Type;
                                Path    : in String) is
   begin
      Context.Path := Ada.Strings.Unbounded.To_Unbounded_String (Path);
   end Set_Keystore_Path;

   --  ------------------------------
   --  Open the keystore file using the password password.
   --  ------------------------------
   procedure Open_Keystore (Context  : in out Context_Type) is
   begin
      Context.Wallet.Open (Password => Context.Provider.Get_Password,
                           Path     => Context.Wallet_File.all);
   end Open_Keystore;

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
      Context.Provider := AKT.Passwords.Input.Create (False);
      GC.Set_Usage (Config => Context.Command_Config,
                    Usage  => "[switchs] command [arguments]",
                    Help   => "akt - tool to store and protect your sensitive data");
      GC.Define_Switch (Config => Context.Command_Config,
                        Output => Context.Verbose'Access,
                        Switch => "-v",
                        Help   => "Enable verbose execution");
      GC.Define_Switch (Config => Context.Command_Config,
                        Output => Context.Debug'Access,
                        Switch => "-d",
                        Long_Switch => "--debug",
                        Help   => "Enable debug execution");
      GC.Define_Switch (Config => Context.Command_Config,
                        Output => Context.Wallet_File'Access,
                        Switch => "-f:",
                        Long_Switch => "--file=",
                        Help   => "Defines the path for the wallet file");
      GC.Define_Switch (Config => Context.Command_Config,
                        Output => Context.Password_File'Access,
                        Long_Switch => "--passfile=",
                        Help   => "Read the file that contains the password");
      GC.Define_Switch (Config => Context.Command_Config,
                        Output => Context.Unsafe_Password'Access,
                        Long_Switch => "--passfd=",
                        Help   => "Read the password from the pipe with"
                          & " the given file descriptor");
      GC.Define_Switch (Config => Context.Command_Config,
                        Output => Context.Unsafe_Password'Access,
                        Long_Switch => "--passsocket=",
                        Help   => "The password is passed within the socket connection");
      GC.Define_Switch (Config => Context.Command_Config,
                        Output => Context.Password_Env'Access,
                        Long_Switch => "--passenv=",
                        Help   => "Read the environment variable that contains"
                        & " the password (not safe)");
      GC.Define_Switch (Config => Context.Command_Config,
                        Output => Context.Unsafe_Password'Access,
                        Switch => "-p:",
                        Long_Switch => "--password=",
                        Help   => "The password is passed within the command line (not safe)");
      GC.Initialize_Option_Scan (Stop_At_First_Non_Switch => True);

      Driver.Set_Description ("akt - tool to store and protect your sensitive data");
      Driver.Set_Usage ("[-v] [-d] [-f keystore] [-p <password>] <command> [<args>]" & ASCII.LF &
                          "where:" & ASCII.LF &
                          "  -v           Verbose execution mode" & ASCII.LF &
                          "  -d           Debug execution mode" & ASCII.LF &
                          "  -f keystore  The keystore file to use");
      Driver.Add_Command ("help", "print some help", Help_Command'Access);
      Driver.Add_Command ("set", "insert or update a value in the keystore", Set_Command'Access);
      Driver.Add_Command ("get", "get a value from the keystore", Get_Command'Access);
      Driver.Add_Command ("create", "create the keystore", Create_Command'Access);
      Driver.Add_Command ("list", "list values of the keystore", List_Command'Access);
      Driver.Add_Command ("remove", "remove values from the keystore", Remove_Command'Access);
      Driver.Add_Command ("edit", "edit the value with an external editor", Edit_Command'Access);
   end Initialize;

   procedure Parse (Context   : in out Context_Type;
                    Arguments : out Util.Commands.Dynamic_Argument_List) is
   begin
      GC.Getopt (Config => Context.Command_Config);
      Util.Commands.Parsers.GNAT_Parser.Get_Arguments (Arguments, GC.Get_Argument);

      if Context.Verbose or Context.Debug then
         AKT.Configure_Logs (Debug => Context.Debug, Verbose => Context.Verbose);
      end if;

      if Context.Password_File'Length > 0 then
         Context.Set_Password_Provider (Passwords.Files.Create (Context.Password_File.all));
      elsif Context.Unsafe_Password'Length > 0 then
         Context.Set_Password_Provider (Passwords.Unsafe.Create (Context.Unsafe_Password.all));
      end if;
   end Parse;

end AKT.Commands;
