-----------------------------------------------------------------------
--  akt-commands -- Ada Keystore Tool commands
--  Copyright (C) 2019, 2020, 2022, 2023 Stephane Carrez
--  Written by Stephane Carrez (Stephane.Carrez@gmail.com)
--  SPDX-License-Identifier: Apache-2.0
-----------------------------------------------------------------------
with System.Multiprocessors;
with Ada.Command_Line;
with Ada.Text_IO;
with Ada.Unchecked_Deallocation;
with Util.Files;
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
with AKT.Commands.Info;
with AKT.Commands.Config;
with AKT.Commands.Mount;
with AKT.Commands.OTP;
with AKT.Commands.Genkey;
with Keystore.Passwords.Input;
with Keystore.Passwords.Files;
with Keystore.Passwords.Unsafe;
with Keystore.Passwords.Cmds;
package body AKT.Commands is

   use type Keystore.Passwords.Provider_Access;
   use type Keystore.Header_Slot_Count_Type;
   use type Keystore.Passwords.Keys.Key_Provider_Access;

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
   Info_Command            : aliased AKT.Commands.Info.Command_Type;
   Config_Command          : aliased AKT.Commands.Config.Command_Type;
   OTP_Command             : aliased AKT.Commands.OTP.Command_Type;
   Genkey_Command          : aliased AKT.Commands.Genkey.Command_Type;
   Driver                  : Drivers.Driver_Type;

   --  ------------------------------
   --  Print the command usage.
   --  ------------------------------
   procedure Usage (Args    : in Argument_List'Class;
                    Context : in out Context_Type;
                    Name    : in String := "";
                    Error   : in String := "") is
   begin
      if Error'Length > 0 then
         Log.Error ("{0}", Error);
      end if;
      if Name'Length > 0 then
         Driver.Usage (Args, Context, Name);
      else
         GC.Display_Help (Context.Command_Config);
      end if;
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end Usage;

   --  ------------------------------
   --  Open the keystore file using the password password.
   --  When `Use_Worker` is set, a workers of N tasks is created and assigned to the keystore
   --  for the decryption and encryption process.
   --  ------------------------------
   procedure Open_Keystore (Context    : in out Context_Type;
                            Args       : in Argument_List'Class;
                            Use_Worker : in Boolean := False) is
   begin
      Setup_Password_Provider (Context);
      Setup_Key_Provider (Context);

      Context.Wallet.Open (Path      => Context.Get_Keystore_Path (Args),
                           Data_Path => Context.Data_Path.all,
                           Config    => Context.Config,
                           Info      => Context.Info);

      if not Context.No_Password_Opt or else Context.Info.Header_Count = 0 then
         if Context.Key_Provider /= null then
            Context.Wallet.Set_Master_Key (Context.Key_Provider.all);
         end if;
         if Context.Provider = null then
            Context.Provider := Keystore.Passwords.Input.Create (-("Enter password: "), False);
         end if;

         Context.Wallet.Unlock (Context.Provider.all, Context.Slot);
      else
         Context.GPG.Load_Secrets (Context.Wallet);

         Context.Wallet.Set_Master_Key (Context.GPG);

         Context.Wallet.Unlock (Context.GPG, Context.Slot);
      end if;

      if Use_Worker and then Context.Worker_Count > 1 then
         Context.Workers := new Keystore.Task_Manager (Context.Worker_Count);
         Keystore.Start (Context.Workers);
         Context.Wallet.Set_Work_Manager (Context.Workers);
      end if;
   end Open_Keystore;

   --  ------------------------------
   --  Open the keystore file and change the password.
   --  ------------------------------
   procedure Change_Password (Context      : in out Context_Type;
                              Args         : in Argument_List'Class;
                              New_Password : in out Keystore.Passwords.Provider'Class;
                              Config       : in Keystore.Wallet_Config;
                              Mode         : in Keystore.Mode_Type) is
   begin
      Context.Wallet.Open (Path      => Context.Get_Keystore_Path (Args),
                           Data_Path => Context.Data_Path.all,
                           Config    => Context.Config,
                           Info      => Context.Info);

      if not Context.No_Password_Opt or else Context.Info.Header_Count = 0 then
         if Context.Key_Provider /= null then
            Context.Wallet.Set_Master_Key (Context.Key_Provider.all);
         end if;

         Context.Wallet.Unlock (Context.Provider.all, Context.Slot);
         Context.Wallet.Set_Key (Password     => Context.Provider.all,
                                 New_Password => New_Password,
                                 Config       => Config,
                                 Mode         => Mode);
      else
         Context.GPG.Load_Secrets (Context.Wallet);
         Context.Wallet.Set_Master_Key (Context.GPG);
         Context.Wallet.Unlock (Context.GPG, Context.Slot);
         Context.Wallet.Set_Key (Password     => Context.GPG,
                                 New_Password => New_Password,
                                 Config       => Config,
                                 Mode         => Mode);
      end if;

   end Change_Password;

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
      Intl.Initialize ("akt", AKT.Configs.PREFIX & "/share/locale");

      Context.Worker_Count := Positive (System.Multiprocessors.Number_Of_CPUs);

      GC.Set_Usage (Config => Context.Command_Config,
                    Usage  => "[switchs] command [arguments]",
                    Help   => -("akt - tool to store and protect your sensitive data"));
      GC.Define_Switch (Config => Context.Command_Config,
                        Output => Context.Version'Access,
                        Switch => "-V",
                        Long_Switch => "--version",
                        Help   => -("Print the version"));
      GC.Define_Switch (Config => Context.Command_Config,
                        Output => Context.Verbose'Access,
                        Switch => "-v",
                        Long_Switch => "--verbose",
                        Help   => -("Verbose execution mode"));
      GC.Define_Switch (Config => Context.Command_Config,
                        Output => Context.Debug'Access,
                        Switch => "-vv",
                        Long_Switch => "--debug",
                        Help   => -("Enable debug execution"));
      GC.Define_Switch (Config => Context.Command_Config,
                        Output => Context.Dump'Access,
                        Switch => "-vvv",
                        Long_Switch => "--debug-dump",
                        Help   => -("Enable debug dump execution"));
      GC.Define_Switch (Config => Context.Command_Config,
                        Output => Context.Zero'Access,
                        Switch => "-z",
                        Long_Switch => "--zero",
                        Help   => -("Erase and fill with zeros instead of random values"));
      GC.Define_Switch (Config => Context.Command_Config,
                        Output => Context.Config_File'Access,
                        Switch => "-c:",
                        Long_Switch => "--config=",
                        Argument => "PATH",
                        Help   => -("Defines the path for akt global configuration"));
      GC.Define_Switch (Config => Context.Command_Config,
                        Output => Context.Worker_Count'Access,
                        Switch => "-t:",
                        Long_Switch => "--thread=",
                        Initial  => Context.Worker_Count,
                        Argument => "COUNT",
                        Help   => -("Number of threads for the encryption/decryption process"));
      GC.Initialize_Option_Scan (Stop_At_First_Non_Switch => True);

      Driver.Set_Description (-("akt - tool to store and protect your sensitive data"));
      Driver.Set_Usage (-("[-V] [-v] [-vv] [-vvv] [-c path] [-t count] [-z] " &
                          "<command> [<args>]" & ASCII.LF &
                          "where:" & ASCII.LF &
                          "  -V           Print the tool version" & ASCII.LF &
                          "  -v           Verbose execution mode" & ASCII.LF &
                          "  -vv          Debug execution mode" & ASCII.LF &
                          "  -vvv         Dump execution mode" & ASCII.LF &
                          "  -c path      Defines the path for akt " &
                          "global configuration" & ASCII.LF &
                          "  -t count     Number of threads for the " &
                          "encryption/decryption process" & ASCII.LF &
                          "  -z           Erase and fill with zeros instead of random values"));
      Driver.Add_Command ("help",
                          -("print some help"),
                          Help_Command'Access);
      Driver.Add_Command ("config",
                          -("get or set global options"),
                          Config_Command'Access);
      Driver.Add_Command ("set",
                          -("insert or update a value in the keystore"),
                          Set_Command'Access);
      Driver.Add_Command ("store",
                          -("read the standard input and insert or update the"
                            & " content in the keystore"),
                          Store_Command'Access);
      Driver.Add_Command ("get",
                          -("get a value from the keystore"),
                          Get_Command'Access);
      Driver.Add_Command ("extract",
                          -("get a value from the keystore"),
                          Extract_Command'Access);
      Driver.Add_Command ("create",
                          -("create the keystore"),
                          Create_Command'Access);
      Driver.Add_Command ("list",
                          -("list values of the keystore"),
                          List_Command'Access);
      Driver.Add_Command ("remove",
                          -("remove values from the keystore"),
                          Remove_Command'Access);
      Driver.Add_Command ("edit",
                          -("edit the value with an external editor"),
                          Edit_Command'Access);
      Driver.Add_Command ("password-set",
                          -("change the password"),
                          Set_Password_Command'Access);
      Driver.Add_Command ("password-add",
                          -("add a password"),
                          Add_Password_Command'Access);
      Driver.Add_Command ("password-remove",
                          -("remove a password"),
                          Remove_Password_Command'Access);
      Driver.Add_Command ("info",
                          -("report information about the keystore"),
                          Info_Command'Access);
      Driver.Add_Command ("otp",
                          -("generate a one time password or manage OATH secrets"),
                          OTP_Command'Access);
      Driver.Add_Command ("genkey",
                          -("generate or manage named keys"),
                          Genkey_Command'Access);
      AKT.Commands.Mount.Register (Driver);
   end Initialize;

   procedure Flush_Input is
      C         : Character;
      Available : Boolean;
   begin
      loop
         Ada.Text_IO.Get_Immediate (C, Available);
         exit when not Available;
      end loop;

   exception
      when Ada.Text_IO.End_Error =>
         null;
   end Flush_Input;

   function Confirm (Message : in String) return Boolean is
   begin
      Flush_Input;
      Util.Commands.Put_Raw ("akt: " & Message & " ");
      declare
         Answer : constant String := Ada.Text_IO.Get_Line;
      begin
         return Answer = "Y" or else Answer = "y";
      end;

   exception
      when Ada.Text_IO.End_Error =>
         return False;
   end Confirm;

   --  ------------------------------
   --  Setup the command before parsing the arguments and executing it.
   --  ------------------------------
   procedure Setup (Config  : in out GC.Command_Line_Configuration;
                    Context : in out Context_Type) is
   begin
      GC.Define_Switch (Config => Config,
                        Output => Context.Wallet_File'Access,
                        Switch => "-k:",
                        Long_Switch => "--keystore=",
                        Argument => "PATH",
                        Help   => -("Defines the path for the keystore file"));
      GC.Define_Switch (Config => Config,
                        Output => Context.Data_Path'Access,
                        Switch => "-d:",
                        Long_Switch => "--data-path=",
                        Argument => "PATH",
                        Help   => -("The directory which contains the keystore data blocks"));
      GC.Define_Switch (Config => Config,
                        Output => Context.Password_File'Access,
                        Long_Switch => "--passfile=",
                        Argument => "PATH",
                        Help   => -("Read the file that contains the password"));
      GC.Define_Switch (Config => Config,
                        Output => Context.Unsafe_Password'Access,
                        Long_Switch => "--passfd=",
                        Argument => "NUM",
                        Help   => -("Read the password from the pipe with"
                          & " the given file descriptor"));
      GC.Define_Switch (Config => Config,
                        Output => Context.Unsafe_Password'Access,
                        Long_Switch => "--passsocket=",
                        Help   => -("The password is passed within the socket connection"));
      GC.Define_Switch (Config => Config,
                        Output => Context.Password_Env'Access,
                        Long_Switch => "--passenv=",
                        Argument => "NAME",
                        Help   => -("Read the environment variable that contains"
                        & " the password (not safe)"));
      GC.Define_Switch (Config => Config,
                        Output => Context.Unsafe_Password'Access,
                        Switch => "-p:",
                        Long_Switch => "--password=",
                        Help   => -("The password is passed within the command line (not safe)"));
      GC.Define_Switch (Config => Config,
                        Output => Context.Password_Askpass'Access,
                        Long_Switch => "--passask",
                        Help   => -("Run the ssh-askpass command to get the password"));
      GC.Define_Switch (Config => Config,
                        Output => Context.Password_Command'Access,
                        Long_Switch => "--passcmd=",
                        Argument => "COMMAND",
                        Help   => -("Run the command to get the password"));
      GC.Define_Switch (Config => Config,
                        Output => Context.Password_Key'Access,
                        Long_Switch => "--passkey=",
                        Argument => "NAME",
                        Help   => -("The password is read from a key file"));
      GC.Define_Switch (Config => Config,
                        Output => Context.Wallet_Key_File'Access,
                        Long_Switch => "--wallet-key-file=",
                        Argument => "PATH",
                        Help   => -("Read the file that contains the wallet keys"));
      GC.Define_Switch (Config => Config,
                        Output => Context.Wallet_Key'Access,
                        Long_Switch => "--wallet-key=",
                        Argument => "NAME",
                        Help   => -("The wallet master key is read from a named key file"));
   end Setup;

   procedure Setup_Password_Provider (Context : in out Context_Type) is
   begin
      if Context.Password_Askpass then
         Context.Provider := Keystore.Passwords.Cmds.Create ("ssh-askpass");
      elsif Context.Password_Command'Length > 0 then
         Context.Provider := Keystore.Passwords.Cmds.Create (Context.Password_Command.all);
      elsif Context.Password_File'Length > 0 then
         Context.Provider := Keystore.Passwords.Files.Create (Context.Password_File.all);
      elsif Context.Password_Command'Length > 0 then
         Context.Provider := Keystore.Passwords.Cmds.Create (Context.Password_Command.all);
      elsif Context.Unsafe_Password'Length > 0 then
         Context.Provider := Keystore.Passwords.Unsafe.Create (Context.Unsafe_Password.all);
      elsif Context.Password_Key'Length > 0 then
         declare
            Path : constant String := Get_Named_Key_Path (Context.Password_Key.all);
         begin
            Context.Provider := Keystore.Passwords.Files.Create (Path);
         end;
      else
         Context.No_Password_Opt := True;
      end if;
      Context.Key_Provider := Keystore.Passwords.Keys.Create (Keystore.DEFAULT_WALLET_KEY);
   end Setup_Password_Provider;

   procedure Setup_Key_Provider (Context : in out Context_Type) is
   begin
      if Context.Wallet_Key_File'Length > 0 then
         Context.Key_Provider := Keystore.Passwords.Files.Create (Context.Wallet_Key_File.all);
      elsif Context.Wallet_Key'Length > 0 then
         declare
            Path : constant String := Get_Named_Key_Path (Context.Wallet_Key.all);
         begin
            Context.Key_Provider := Keystore.Passwords.Files.Create (Path);
         end;
      end if;
   end Setup_Key_Provider;

   procedure Initialize (Context : in out Keystore.Passwords.GPG.Context_Type) is
   begin
      if AKT.Configs.Exists (AKT.Configs.GPG_CRYPT_CONFIG) then
         Context.Set_Encrypt_Command (AKT.Configs.Get (AKT.Configs.GPG_CRYPT_CONFIG));
      end if;
      if AKT.Configs.Exists (AKT.Configs.GPG_DECRYPT_CONFIG) then
         Context.Set_Decrypt_Command (AKT.Configs.Get (AKT.Configs.GPG_DECRYPT_CONFIG));
      end if;
      if AKT.Configs.Exists (AKT.Configs.GPG_LIST_CONFIG) then
         Context.Set_List_Key_Command (AKT.Configs.Get (AKT.Configs.GPG_LIST_CONFIG));
      end if;
   end Initialize;

   procedure Parse (Context   : in out Context_Type;
                    Arguments : out Util.Commands.Dynamic_Argument_List) is
   begin
      GC.Getopt (Config => Context.Command_Config);
      Util.Commands.Parsers.GNAT_Parser.Get_Arguments (Arguments, GC.Get_Argument);

      if Context.Debug or else Context.Verbose or else Context.Dump then
         AKT.Configure_Logs (Debug   => Context.Debug,
                             Dump    => Context.Dump,
                             Verbose => Context.Verbose);
      end if;

      AKT.Configs.Initialize (Context.Config_File.all);
      Initialize (Context.GPG);

      if Context.Version then
         Util.Commands.Put_Raw_Line (AKT.Configs.RELEASE);
         return;
      end if;

      Context.Config.Randomize := not Context.Zero;
      declare
         Cmd_Name : constant String := Arguments.Get_Command_Name;
      begin
         if Cmd_Name'Length = 0 then
            AKT.Commands.Log.Error (-("missing command name to execute."));
            AKT.Commands.Usage (Arguments, Context);
            Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
            return;
         end if;
         AKT.Commands.Execute (Cmd_Name, Arguments, Context);

      exception
         when GNAT.Command_Line.Invalid_Parameter =>
            AKT.Commands.Log.Error (-("missing option parameter"));
            raise Error;
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
      if not (Low in Positive'Range) or else not (High in Positive'Range) then
         AKT.Commands.Log.Error (-("value is out of range"));
         raise Error;
      end if;
      if Low > High then
         AKT.Commands.Log.Error (-("the min counter is greater than max counter"));
         raise Error;
      end if;
      Config.Min_Counter := Positive (Low);
      Config.Max_Counter := Positive (High);

   exception
      when Error =>
         raise;

      when others =>
         AKT.Commands.Log.Error (-("invalid counter range: {0}"), Value);
         AKT.Commands.Log.Error (-("valid format are 'MAX_COUNTER' or "
                                 & "'MIN_COUNTER:MAX_COUNTER'"));
         AKT.Commands.Log.Error (-("counters must be positive integers"));
         raise Error;

   end Parse_Range;

   --  ------------------------------
   --  Get the keystore file path.
   --  ------------------------------
   function Get_Keystore_Path (Context : in out Context_Type;
                               Args    : in Argument_List'Class) return String is
   begin
      if Context.Wallet_File'Length > 0 then
         Context.First_Arg := 1;
         return Context.Wallet_File.all;
      elsif Args.Get_Count > 0 then
         Context.First_Arg := 2;
         return Args.Get_Argument (1);
      else
         raise No_Keystore_File;
      end if;
   end Get_Keystore_Path;

   --  ------------------------------
   --  Get the path to the named key (created and managed by genkey command).
   --  ------------------------------
   function Get_Named_Key_Path (Name : in String) return String is
      Dir : constant String := AKT.Configs.Get_Directory_Key_Path;
   begin
      if Dir'Length = 0 then
         Log.Error (-("no valid directory keys can be created"));
         raise Error with "no valid directory keys";
      end if;
      return Util.Files.Compose (Dir, Name & ".key");
   end Get_Named_Key_Path;

   overriding
   procedure Finalize (Context : in out Context_Type) is
      use type Keystore.Task_Manager_Access;
      procedure Free is
        new Ada.Unchecked_Deallocation (Object => Keystore.Passwords.Provider'Class,
                                        Name   => Keystore.Passwords.Provider_Access);
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
