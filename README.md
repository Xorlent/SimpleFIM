# SimpleFIM
Flexible PowerShell-based file integrity monitor with Syslog and SMTP alerting functionality.  When we began doing research and getting demos of various commercial products, they were either not configurable so you could not monitor spoecific application folders, or they were overly complicated and expensive for such a simple task.  
SimpleFIM is designed to allow anyone to implement no-cost file integrity monitoring on critical Windows assets in a matter of minutes.

## Prerequisites
1. A Windows machine with PowerShell
2. PSSQLite, which can be added via the PowerShell Install-Module command (Install-Module PSSQLite) or via Github at https://github.com/RamblingCookieMonster/PSSQLite.  If you run the installer, it will attempt to install the module for you.
3. (optional) A Syslog collector (Disabled by default, but it is recommended you specify one)
4. (optional) A SMTP relay host (Disabled by default, but if you do not have a Syslog collector, use this)
5. Internet access is needed if you want the installer to add the PSSQLite module.  Otherwise, you can install this module manually.

## Installation
1. Download the latest release .ZIP file.
2. Right-click the downloaded file, click Properties, and click "Unblock"
3. Extract the .ZIP to a single directory.
5. Launch PowerShell as an administrator, navigate to the directory with the unzipped files.
6. Type .\SimpleFIM-Install.ps1 to run the installer.
7. Follow the directions at the end of the process to complete SimpleFIM setup.

## Operation
### Configuration
#### SimpleFIM-Config.xml
Edit this file to specify your Syslog and SMTP server details.  The installer will rename any existing config file to SimpleFIM-Config.backup.
### Two files control the execution of the FIM script
#### SimpleFIM.ps1
This is configured to execute once per hour by default.  Depending on the number of folders to monitor, the process can take some time, so be sure to profile its performance prior to setting the final schedule.  4 CPU cores are highly recommended for any machine running this process.  Real-world testing shows first-run performance of 70,000 files per hour with minimal CPU usage and subsequent run performance of 25,000 files per minute with high single-core CPU usage.  
#### CycleErrorLogs.cmd
This is configured to execute once per day by default.  The script simply renames any error log to CalchashesErr.MMDDYY  
The .ps1 and .cmd file should both be placed in C:\Program Files\FIM.  Ensure only Administrators have access to modify the contents of this folder.  
### User Account
A local user named, “fim” is created by the installer with a unique, strong password.  The user account should be configured with no password expiration and should not be added to any additional groups.  
### Group Policy Settings
This setting is handled by the installer.  Open mmc.exe and load the Local Group Policy.  The new “fim” user needs to be added to the, “Log on as a batch job” right.  This can be found in Computer Configuration->Windows Settings->Local Policies->User Rights Assignments  
### Files and Folders to monitor
"C:\Windows\ScanList.log"
This is the file containing the list of files and folders that should be monitored by the FIM script.  The FIM batch user needs read, list access to every location you specify.  Each file or folder to scan should be on its own line.  Use a “|” to terminate each entry (REQUIRED).  Single line comments following each entry are permitted.  
Example:  
D:\Program Files\Apache9.45\lib| # Libraries directory
### Runtime files
By default, the installer creates a runtime folder C:\FIM, with write permissions for FIM batch account.  
#### "C:\FIM\Hashes.sqdb"
This is the SQLite database that holds all the hash information for files and folders being monitored.  The only user that needs access to this file is the FIM batch account.  
#### "C:\FIM\Calchashes.log"
This file is generated/populated any time a monitored file changes and will be a human-readable running log of any changes over time.  Changes are also sent to your configured Syslog destination.  
#### "C:\FIM\CalchashesErr.log"
This file is generated/populated any time a runtime error occurs (typically this would be file read errors or incorrectly specified file/folders in ScanList.log).  Errors are also sent to your configured Syslog destination.  
## Troubleshooting
### I need to edit a scheduled task but do not know the password for the "fim" user account
1. Open Computer Management and reset the password for the fim user.  Always use a complex password with a minimum length of 15 characters.
2. Once the password has been changed, open Task Scheduler and edit both SimpleFIM tasks, "Simple FIM Run Process" and "Simple FIM Cycle Error Log," specifying this new password when saving the task.
