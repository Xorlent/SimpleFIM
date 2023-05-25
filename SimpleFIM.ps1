Import-Module PSSQLite
$ConfigFile = 'C:\Program Files\FIM\SimpleFIM-Config.xml'
$ConfigParams = [xml](get-content $ConfigFile)
$VirusTotalURL = 'https://www.virustotal.com/gui/file/'

# Initialize configuration variables from config xml file
$SyslogTarget = $ConfigParams.configuration.syslog.fqdn.value
$SyslogPort = $ConfigParams.configuration.syslog.port.value
$SMTPServer = $ConfigParams.configuration.smtp.fqdn.value
$SMTPPort = $ConfigParams.configuration.smtp.port.value
$FromAddress = $ConfigParams.configuration.smtp.fromEmail.value
$ToAddress = $ConfigParams.configuration.smtp.toEmail.value
$FIMDirList = $ConfigParams.configuration.filepaths.monitoredList.value
$databasePath = $ConfigParams.configuration.filepaths.databasePath.value
$changeLog = $ConfigParams.configuration.filepaths.changeLog.value
$errorLog = $ConfigParams.configuration.filepaths.errorLog.value

# Flag to see if this is a first run or not
$DBExists = 0

# This computer's NETBIOS name, used for Syslog
$FIMHostname = $env:COMPUTERNAME

# Syslog Function ---------------------
 
# The SendTo-Syslog function is adapted from https://www.sans.org/blog/powershell-function-to-send-udp-syslog-message-packets/ with many thanks!
function SendTo-SysLog
{
 
   param ([String]$Facility, [String]$Severity, [String]$Content, [String]$Tag)
 
switch -regex ($Facility)
    {
    'kern' {$Facility = 0 * 8 ; break }
    'user' {$Facility = 1 * 8 ; break }
    'mail' {$Facility = 2 * 8 ; break }
    'system' {$Facility = 3 * 8 ; break }
    'auth' {$Facility = 4 * 8 ; break }
    'syslog' {$Facility = 5 * 8 ; break }
    'lpr' {$Facility = 6 * 8 ; break }
    'news' {$Facility = 7 * 8 ; break }
    'uucp' {$Facility = 8 * 8 ; break }
    'cron' {$Facility = 9 * 8 ; break }
    'authpriv' {$Facility = 10 * 8 ; break }
    'ftp' {$Facility = 11 * 8 ; break }
    'ntp' {$Facility = 12 * 8 ; break }
    'logaudit' {$Facility = 13 * 8 ; break }
    'logalert' {$Facility = 14 * 8 ; break }
    'clock' {$Facility = 15 * 8 ; break }
    'local0' {$Facility = 16 * 8 ; break }
    'local1' {$Facility = 17 * 8 ; break }
    'local2' {$Facility = 18 * 8 ; break }
    'local3' {$Facility = 19 * 8 ; break }
    'local4' {$Facility = 20 * 8 ; break }
    'local5' {$Facility = 21 * 8 ; break }
    'local6' {$Facility = 22 * 8 ; break }
    'local7' {$Facility = 23 * 8 ; break }
    default {$Facility = 23 * 8 } #Default is local7
    }
 
switch -regex ($Severity)
    {
    '^em' {$Severity = 0 ; break } #Emergency
    '^a' {$Severity = 1 ; break } #Alert
    '^c' {$Severity = 2 ; break } #Critical
    '^er' {$Severity = 3 ; break } #Error
    '^w' {$Severity = 4 ; break } #Warning
    '^n' {$Severity = 5 ; break } #Notice
    '^i' {$Severity = 6 ; break } #Informational
    '^d' {$Severity = 7 ; break } #Debug
    default {$Severity = 5 } #Default is Notice
    }
$privalue = [int]$Facility + [int]$Severity
$pri = "<" + $privalue + ">"
 
# Note that the timestamp is local time on the originating computer, not UTC.
if ($(get-date).day -lt 10) { $timestamp = $(get-date).tostring("MMM d HH:mm:ss") } else { $timestamp = $(get-date).tostring("MMM dd HH:mm:ss") }
 
$header = $timestamp + " " + $FIMHostname + " "
 
$msg = $pri + $header + $Tag + ": " + $Content
 
# Convert message to array of ASCII bytes.
$bytearray = $([System.Text.Encoding]::ASCII).getbytes($msg)
 
# RFC3164 Section 4.1: "The total length of the packet MUST be 1024 bytes or less."
# "Packet" is not "PRI + HEADER + MSG", and IP header = 20, UDP header = 8, hence:
if ($bytearray.count -gt 996) { $bytearray = $bytearray[0..995] }
 
# Send the Syslog message...
if ($SyslogTarget -ne "syslog.hostname.here") {
 $UdpClient = New-Object System.Net.Sockets.UdpClient $SyslogTarget, $SyslogPort
 $UdpClient.Send($bytearray, $bytearray.length) | out-null
 }
} # End SendTo-SysLog
 
# End Syslog Function ---------------------
 
# Check if the DB file exists.  Will be used to suppress output/logging on first run.
if ((Test-Path -Path $databasePath -PathType Leaf)) {
   $DBExists = 1
   }
 
# Open and/or initialize database
$DBconn = New-SqliteConnection -DataSource $databasePath
Invoke-SqliteQuery -Connection $DBconn -Query "CREATE TABLE IF NOT EXISTS Hashes (FilePath TEXT PRIMARY KEY, LastModified TEXT, LastHash TEXT, CurrentHash TEXT)"
Invoke-SqliteQuery -Connection $DBconn -Query "CREATE TABLE IF NOT EXISTS Changes (FilePath TEXT, ChangeTime TEXT, LastHash TEXT, CurrentHash TEXT)"
 
# Get the current date and time
$now = Get-Date
 
# Initialize email alerts
$QueuedChangesEmail = 0
$ChangesEmailBody = @'
SimpleFIM new and changed files digest:
******************************
 
'@
$QueuedErrorsEmail = 0
$ErrorsEmailBody = @'
SimpleFIM errors digest:
******************************
 
'@
 
# Import and iterate through the list of directories to scan (all will be recursive)
Get-Content $FIMDirList | Where-Object { $_ -notmatch '^#' } | ForEach-Object {
   $fields = $_.Split("|")
   $scanDir = $fields[0]
 
   # Check for the existence of the specified file or folder
   if ((Test-Path -Path $scanDir -PathType Any)) {
 
   # Loop through all files in the directory tree and generate SHA256 hashes
       Get-ChildItem -Recurse -File $scanDir | ForEach-Object {
           $filePath = $_.FullName
           $lastModified = $_.LastWriteTime
           $lastHash = $currentHash = $null
 
           # Check if the file is already in the database
           $query = "SELECT * FROM Hashes WHERE FilePath = '$filePath'"
           $existingRecord = Invoke-SqliteQuery -Connection $DBconn -Query $query
 
           # Calculate the file's current hash value
           $currentHash = Get-FileHash $filePath -Algorithm SHA256 | Select-Object -ExpandProperty Hash
 
           # If the hash was already previously calculated (it's in the database)
           if ($existingRecord) {
               # Get the most current hash from the database
               $lastHash = $existingRecord.CurrentHash
 
               # Verify we got a valid hash (we could read the file)
               if ($currentHash -ne $null) {
                   # Compare the hash in the DB with the one calculated from the file on drive.  If it changed, update the DB
                   if ($currentHash -ne $lastHash) {
                       # Log the change in the Changes table
                       $query = "INSERT INTO Changes (FilePath, ChangeTime, LastHash, CurrentHash) VALUES ('$filePath', '$now', '$lastHash', '$currentHash')"
                       Invoke-SqliteQuery -Connection $DBconn -Query $query
                       
                       # Log the changed file details to SIEM and local filesystem
                       $changeDetails = $now.ToString("u") + " | Path: " + $filePath + " | Last: " + $lastHash + " | New: " + $currentHash
                       SendTo-SysLog "system" "warning" $changeDetails "SimpleFIM"
                       Add-Content -Path $changeLog -Value $changeDetails
 
                       # Add the item to our email notification body and set the queued email flag
                       $ChangesEmailBody = $ChangesEmailBody + $changeDetails + " | " + $VirusTotalURL + $currentHash + "`r`n"
                       $QueuedChangesEmail = 1
 
                       # Update the LastModified and CurrentHash columns in the Hashes table
                       $query = "UPDATE Hashes SET LastModified = '$lastModified', CurrentHash = '$currentHash', LastHash = '$lastHash' WHERE FilePath = '$filePath'"
                       Invoke-SqliteQuery -Connection $DBconn -Query $query
                       }
                   }
               else {
                   # We could not get the hash for the file on disk
                   $errorDetails = $now.ToString("u") + " | Path: " + $filePath + " | --> Could not get hash.  Ensure the fim batch account has file/folder read and list permissions."
                   if (-not(Test-Path -Path $errorLog -PathType Leaf)){SendTo-SysLog "system" "error" $errorDetails "SimpleFIM"}
                   Add-Content -Path $errorLog -Value $errorDetails
                   
                   # Add the item to our email alert body and set the queued email flag
                   $ErrorsEmailBody = $ErrorsEmailBody + $errorDetails + "`r`n"
                   $QueuedErrorsEmail = 1
                   }
               }
           else {
               if ($currentHash -ne $null) {
                   # Insert a brand new record into the Hashes table
                   $query = "INSERT INTO Hashes (FilePath, LastModified, CurrentHash) VALUES ('$filePath', '$lastModified', '$currentHash')"
                   Invoke-SqliteQuery -Connection $DBconn -Query $query
 
                   # Log the new file if the database was pre-existing
                   if($DBExists -eq 1){
                       $newFileDetails = $now.ToString("u") + " | Path: " + $filePath + " | --> New file created."
                       SendTo-SysLog "system" "informational" $newFileDetails "SimpleFIM"
                       Add-Content -Path $changeLog -Value $newFileDetails
                       # Add the item to our email notification body and set the queued email flag
                       $ChangesEmailBody = $ChangesEmailBody + $newFileDetails + " | " + $VirusTotalURL + $currentHash + "`r`n"
                       $QueuedChangesEmail = 1
                       }
                   }
               else {
                   # We could not get the hash for the file on disk
                   $errorDetails = $now.ToString("u") + " | Path: " + $filePath + " | --> Could not get hash.  Ensure the fim batch account has file/folder read and list permissions."
                   
                   # Send just one Syslog error per day to prevent sending piles of these alerts on each run.  One alert should clue the admin in that there was a setup issue or permissions have changed.
                   if (-not(Test-Path -Path $errorLog -PathType Leaf)){SendTo-SysLog "system" "error" $errorDetails "SimpleFIM"}
                   Add-Content -Path $errorLog -Value $errorDetails
                   
                   # Add the item to our email alert body and set the queued email flag
                   $ErrorsEmailBody = $ErrorsEmailBody + $errorDetails + "`r`n"
                   $QueuedErrorsEmail = 1
                   }
               }
           } # End Get-Children and iterate through the list of monitored files and directories
 
       } # End test for existence of specified file/folder to monitor (FOUND)
   else {
       # File or folder to scan does not exist!
       $errorDetails = $now.ToString("u") + " | Path: " + $scanDir + " | --> File or folder does not exist on this system or is not readable by the fim batch account."
       SendTo-SysLog "system" "error" $errorDetails "SimpleFIM"
       Add-Content -Path $errorLog -Value $errorDetails
       
       # Add the item to our email alert body and set the queued email flag
       $ErrorsEmailBody = $ErrorsEmailBody + $errorDetails + "`r`n"
       $QueuedErrorsEmail = 1
       } # End test for existence of specified file/folder to monitor (NOT FOUND)
   } # End Get-Content of ScanList.log
 
# Generate SHA256 hash for the FIM list file (to alert on any changes to monitored files/folders list)
Get-ChildItem -File $FIMDirList | ForEach-Object {
   $filePath = $_.FullName
   $lastModified = $_.LastWriteTime
   $lastHash = $currentHash = $null
 
   # Check if the file is already in the database
   $query = "SELECT * FROM Hashes WHERE FilePath = '$filePath'"
   $existingRecord = Invoke-SqliteQuery -Connection $DBconn -Query $query
 
   if ($existingRecord) {
       # Get the most current hash from the database
       $lastHash = $existingRecord.CurrentHash
 
       # Compare the current hash to the one in the database
       $currentHash = Get-FileHash $filePath -Algorithm SHA256 | Select-Object -ExpandProperty Hash
       if ($currentHash -ne $lastHash) {
           # Log the change in the Changes table
           $query = "INSERT INTO Changes (FilePath, ChangeTime, LastHash, CurrentHash) VALUES ('$filePath', '$now', '$lastHash', '$currentHash')"
           Invoke-SqliteQuery -Connection $DBconn -Query $query
 
           # Log changed file details to SIEM and local filesystem
           $changeDetails = $now.ToString("u") + " | Path: " + $filePath + " | Last: " + $lastHash + " | New: " + $currentHash
           SendTo-SysLog "system" "warning" $changeDetails "SimpleFIM"
           Add-Content -Path $changeLog -Value $changeDetails
           
           # Add the item to our email alert body and set the queued email flag
           $ChangesEmailBody = $ChangesEmailBody + $changeDetails + "`r`n"
           $QueuedChangesEmail = 1
           
           # Update the LastModified and CurrentHash columns in the Hashes table
           $query = "UPDATE Hashes SET LastModified = '$lastModified', CurrentHash = '$currentHash', LastHash = '$lastHash' WHERE FilePath = '$filePath'"
           Invoke-SqliteQuery -Connection $DBconn -Query $query
           }
       }
   else {
       # Insert the new record into the Hashes table
       $currentHash = Get-FileHash $filePath -Algorithm SHA256 | Select-Object -ExpandProperty Hash
       $query = "INSERT INTO Hashes (FilePath, LastModified, CurrentHash) VALUES ('$filePath', '$lastModified', '$currentHash')"
       Invoke-SqliteQuery -Connection $DBconn -Query $query
       }
 
   }
 
# Send any queued email messages...
if (($SMTPServer -ne "smtp.hostname.here") -and ($QueuedChangesEmail -eq 1)) {
 $EmailSubject = 'SimpleFIM New and Changed Files Digest FROM ' + $FIMHostname
 Send-MailMessage -From $FromAddress -To $ToAddress -Subject $EmailSubject -Body $ChangesEmailBody -SmtpServer $SMTPServer -Port $SMTPPort
 }
 
if (($SMTPServer -ne "smtp.hostname.here") -and ($QueuedErrorsEmail -eq 1)) {
 $EmailSubject = 'SimpleFIM Errors Digest FROM ' + $FIMHostname
 Send-MailMessage -From $FromAddress -To $ToAddress -Subject $EmailSubject -Body $ErrorsEmailBody -SmtpServer $SMTPServer -Port $SMTPPort
 }
 
# Close the database connection
$DBconn.Close()
