$accountToAdd = 'fim'
$addSwitch = '/add'
$noPromptSwitch = '/Y'

$sidstr = $null

Write-Host "Starting account setup." -ForegroundColor DarkCyan

#  Create FIM user account

$users = $comp.psbase.children | select -expand name
if ($users -like $accountToAdd) {
    Write-Host “$username exists. Skipping account creation to configuring Log On As Batch rights.”
    }
else # User does not exist
    {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
        $GetRequest = 'https://passwordwolf.com/api/?upper=off&length=15&repeat=1'
        $Response = Invoke-RestMethod -Method 'Get' -Uri $GetRequest
        $NewPW = $Response.password

        if ($NewPW.Length -eq "15")
        {
        try
        {
            net user $accountToAdd $NewPW $addSwitch $noPromptSwitch
        }
        catch
        {
            $Err = $_.Exception.Message
            Write-Host $Err
        }
        Write-Host "IMPORTANT This password will be needed to modify Simple FIM scheduled tasks: " $NewPW
        } #end if pwd.length
    }
#  End Create FIM user account

#  "Log on as Batch" : Adapted from a "Log on as a Service" script originally written by Ingo Karstein, http://blog.karstein-consulting.com
#  v1.0, 01/03/2014

try {
	$ntprincipal = new-object System.Security.Principal.NTAccount "$accountToAdd"
	$sid = $ntprincipal.Translate([System.Security.Principal.SecurityIdentifier])
	$sidstr = $sid.Value.ToString()
} catch {
	$sidstr = $null
}


if( [string]::IsNullOrEmpty($sidstr) ) {
	Write-Host "Account creation failed!" -ForegroundColor Red
	exit -1
}

$tmp = [System.IO.Path]::GetTempFileName()

secedit.exe /export /cfg "$($tmp)" 

$c = Get-Content -Path $tmp 

$currentSetting = ""

foreach($s in $c) {
	if( $s -like "SeBatchLogonRight*") {
		$x = $s.split("=",[System.StringSplitOptions]::RemoveEmptyEntries)
		$currentSetting = $x[1].Trim()
	}
}

if( $currentSetting -notlike "*$($sidstr)*" ) {
	if( [string]::IsNullOrEmpty($currentSetting) ) {
		$currentSetting = "*$($sidstr)"
	} else {
		$currentSetting = "*$($sidstr),$($currentSetting)"
	}
	
	$outfile = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeBatchLogonRight = $($currentSetting)
"@

	$tmp2 = [System.IO.Path]::GetTempFileName()
	
	
	Write-Host "Import new settings to Local Security Policy" -ForegroundColor DarkCyan
	$outfile | Set-Content -Path $tmp2 -Encoding Unicode -Force

	Push-Location (Split-Path $tmp2)
	
	try {
		secedit.exe /configure /db "secedit.sdb" /cfg "$($tmp2)" /areas USER_RIGHTS 
	} finally {	
		Pop-Location
	}
} else {
	Write-Host "Account already has ""Logon as a Batch Job"" right." -ForegroundColor DarkCyan
}
#  "End Log on as Batch"

Write-Host "Account setup completed." -ForegroundColor DarkCyan
Write-Host "++++++++++++++++"
Write-Host "Starting Filesystem setup." -ForegroundColor DarkCyan

New-Item -ItemType Directory -Force -Path "C:\FIM"
New-Item -ItemType Directory -Force -Path "C:\Program Files\FIM"

$GrantRights = $accountToAdd + ":(OI)F"
icacls.exe "C:\FIM" /grant $GrantRights

Copy-Item ".\SimpleFIM.ps1" -Destination "C:\Program Files\FIM" -Force
Copy-Item ".\CycleErrorLogs.cmd" -Destination "C:\Program Files\FIM" -Force
Copy-Item ".\ScanList.log" -Destination "C:\Windows" -Force

Write-Host "Filesystem setup completed." -ForegroundColor DarkCyan
Write-Host "++++++++++++++++"
Write-Host "Starting Task Scheduler setup." -ForegroundColor DarkCyan

#  Create scheduled tasks

Register-ScheduledTask -xml (Get-Content '.\CycleErrLogs.xml' | Out-String) -TaskName "Simple FIM Cycle Error Log" -User $ntprincipal -Password $NewPW –Force
Register-ScheduledTask -xml (Get-Content '.\RunSimpleFIM.xml' | Out-String) -TaskName "Simple FIM Run Process" -User $ntprincipal -Password $NewPW –Force
#  End Create scheduled tasks

Write-Host "Task Scheduler setup completed." -ForegroundColor DarkCyan
Write-Host "++++++++++++++++"
Write-Host "Starting PowerShell module install." -ForegroundColor DarkCyan

Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
Install-Module PSSQLite
Set-PSRepository -Name 'PSGallery' -InstallationPolicy Untrusted

Write-Host "PowerShell module install completed." -ForegroundColor DarkCyan
Write-Host "++++++++++++++++"

Write-Host "Next steps:"
Write-Host "  1. Edit C:\Windows\ScanList.log to include the desired monitored files and directories."
Write-Host "  2. Edit C:\Program Files\FIM\SimpleFIM.ps1 and update $SyslogTarget to the FQDN of your Syslog collector host."
Write-Host "  3. For each monitored file or directory, ensure the ""fim"" batch account has read rights."
Write-Host "  4. Enable the ""Simple FIM Cycle Error Log"" and ""Simple FIM Run Process"" scheduled tasks."