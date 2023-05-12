# SimpleFIM
Flexible PowerShell-based file integrity monitor with Syslog functionality

## Prerequisites
1. A Windows machine with PowerShell
2. PSSQLite, which can be added via the PowerShell Install-Module command (Install-Module PSSQLite) or via Github at https://github.com/RamblingCookieMonster/PSSQLite.  If you run the installer, it will attempt to install the module for you.
3. A Syslog collector (Disabled by default, but HIGHLY recommended you specify a target host)
4. Internet access needed if you want the installer to add the PSSQLite module.  Otherwise, you can install this module manually.

## Installation
1. Copy all files to a single directory.
2. Launch PowerShell as an administrator.
3. Run SimpleFIM-Install.ps1
4. Follow the directions at the end of the install process to complete the setup.

## Operation
### Two files control the execution of the FIM script
#### CalcHashes.ps1
This should be executed once per hour or so.  Depending on the number of folders to monitor, the process can take some time, so be sure to profile its performance prior to setting the schedule.  4 CPU cores are highly recommended for any machine running this process.  Real-world testing shows first-run performance of 70,000 files per hour with minimal CPU usage and subsequent run performance of 25,000 files per minute with high single-core CPU usage.  
#### CycleErrorLogs.cmd
This should be executed once per day.  The script simply renames any error log to CalchashesErr.MMDDYY  
The .ps1 and .cmd file should both be placed in C:\Program Files\FIM.  Ensure only Administrators have access to modify the contents of this folder.  
### User Account
Create a local user named, “fim” and assign it a strong password.  The user account should be configured with no password expiration, should not be added to any additional groups, and should have Remote Desktop Services Profile set to “Deny”.  
### Group Policy Settings
Open mmc.exe and load the Local Group Policy.  The new “fim” user needs to be added to the, “Log on as a batch job” right.  This can be found in Computer Configuration->Windows Settings->Local Policies->User Rights Assignments  
### Files and Folders to monitor
$FIMDirList = "C:\Windows\ScanList.log"
This is the file containing the list of files and folders that should be monitored by the FIM script.  The FIM batch user needs read, list access to every location you specify.  Each file or folder to scan should be on its own line.  Use a “|” to terminate the entry (REQUIRED).  Single line comments following each entry are permitted.
Example:
D:\Program Files\Apache9.45\lib| # Libraries directory
### Runtime files
It’s recommended that runtime files are configured for C:\FIM, with write permissions for Administrators and the FIM batch user account only.  
#### $databasePath = "C:\FIM\Hashes.sqdb"
This is the SQLite database that holds all the hash information for files and folders being monitored.  The only user that needs access to this file is the FIM batch account.  
#### $changeLog = "C:\FIM\Calchashes.log"
This file is generated/populated any time a monitored file changes and will be a human-readable running log of any changes over time.  Changes are also sent to your configured Syslog destination.  
#### $errorLog = "C:\FIM\CalchashesErr.log"
 This file is generated/populated any time a runtime error occurs (typically this would be file read errors or incorrectly specified file/folders in ScanList.log).  Errors are also sent to your configured Syslog destination.  
