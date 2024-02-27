<#
	ncas_collector_PSv2.ps1 - NERC CIP Assessment Script for Windows system
        with PowerShell version 2. This script will collect 
        data from the system using default Cmdlets or system
	commands. 
    Author: Don C. Weber (@cutaway)
    Date:   February 27, 2024
#>

<#
	License: 
	Copyright (c) 2024, Cutaway Security, Inc. <dev [@] cutawaysecurity.com>
	
	ncas_collector.ps1 is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	
	ncas_collector.ps1 is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
	Point Of Contact:    Don C. Weber <dev [@] cutawaysecurity.com>
#>

#############################
# Script behavior parameters
#############################
$cutsec_footer       = $true # change to false to disable CutSec footer
$auditor_company     = 'Cutaway Security, LLC' # make empty string to disable
$sitename            = 'plant1' # make empty string to disable
$global:admin_user   = $false # Disable some checks if not running as an Administrator
$global:ps_version   = $PSVersionTable.PSVersion.Major # Get major version to ensure at least PSv3

#############################
# Set up document header information
#############################
$script_name         = 'ncas_collector'
$script_version      = '1.0.0'
$filename_date	     = Get-Date -Format "yyyyddMM_HHmmss"
$start_time_readable = Get-Date -Format "dddd MM/dd/yyyy HH:mm:ss K"
$computername        = $env:ComputerName
$sysdrive            = $env:SystemDrive
$outdir              = $computername + "_" + $filename_date

#############################
# Print Functions
#############################
Function Mkdir-Output{

	Param(
		# Create the output directory in the local directory.
                # Change into the directory to write data.
		$indir = 'Results directory'
	)

    Write-Output "`n#############################"
    Write-Output "# Creating output directory named: $indir"
    Write-Output "#############################"
    if (-not(test-path $indir)){new-item $indir -ItemType Directory | Out-Null}
    Set-Location -Path $indir
}

Function Prt-SectionHeader{

	Param(
		# Enable means to change the setting to the default / insecure state.
		$SectionName = 'Section Name'
	)

    # Write-Output "`n#############################"
    Write-Output "# $SectionName"
    # Write-Output "#############################"
}

Function Prt-ReportHeader{

    Write-Output "`n#############################"
    Write-Output "# NERC CIP Audit Script: $script_name $script_version"
    if ($auditor_company){Write-Output "# Auditing Company: $auditor_company"}
    if ($sitename){Write-Output "# Site / Plant: $sitename"}
    Write-Output "#############################"
    Write-Output "# Hostname: $computername"
    Write-Output "# Start Time: $start_time_readable"
    Write-Output "# PS Version: $ps_version"
    Get-AdminState
    Write-Output "#############################"
}

Function Prt-ReportFooter{

    $stop_time_readable = Get-Date -Format "dddd MM/dd/yyyy HH:mm:ss K"

    Write-Output "`n#############################"
    Write-Output "# $script_name completed"
    Write-Output "# Stop Time: $stop_time_readable"
    Write-Output "#############################`n"

}

Function Prt-CutSec-ReportFooter{

    Write-Output "`n#############################"
    Write-Output "# NERC CIP Audit Script: $script_name $script_version"
    Write-Output "# Brought to you by Cutaway Security, LLC"
    Write-Output "# For assessment and auditing help, contact info [@] cutawaysecurity.com"
    Write-Output "# For script help, contact dev [@] cutawaysecurity.com"
    Write-Output "#############################`n"

}

#############################
# Helper Functions
#############################
# Check for Cmdlet, else use CimInstance
Function Test-CommandExists{
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'stop'
    try {if(Get-Command $command){RETURN $true}}
    Catch {RETURN $false}
    Finally {$ErrorActionPreference=$oldPreference}
} 

# Check for Administrator Role
Function Get-AdminState {
	if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){ 
		Write-Output "# Script Running As Normal User" 
        $global:admin_user = $false
	} else {
		Write-Output "# Script Running As Administrator"
        $global:admin_user = $true
    }
}

#############################
# Information Collection Functions
#############################
Function Get-SystemInfo{
    # Get systeminfo for use with WES-NG
    $sysinfo = systeminfo 
    $sysinfo | Out-file -FilePath systeminfo.txt
}

Function Get-TimezoneInfo{
    $timezone = wmic timezone get caption | Select-Object -Index 2  
    $timezone | Out-file -FilePath timezone.txt
}

Function Get-NtpInfo{
    # Reference: https://docs.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings
    $ntptype = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\W32Time\Parameters").Type
    # Write-Output "Server syncronization setting: $ntptype"
    $outstring = "Server syncronization setting: $ntptype"
    $outstring | Out-file -FilePath ntp_info.txt

    # NTP Server settings
    $ntpservers = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\w32time\Parameters" -Name "NtpServer").NtpServer
    #Write-Output "NTP Server Sources: $ntpservers"
    $outstring = "NTP Server Sources: $ntpservers"
    $outstring | Out-file -Append -FilePath ntp_info.txt
}

Function Get-InstalledSoftware{
    $array = @()

    #Define the variable to hold the location of Currently Installed Programs
    $UninstallKeys= ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall","SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")

    ForEach ($UninstallKey in $UninstallKeys){
        Try {
            # Test to see if the key exists, we don't need contents. Save so it doesn't print
            $installkeyinfo = Get-Item -Path "HKLM:\\$UninstallKey"
        } Catch {
            Continue
        }
        Write-Output "Processing UninstallKey $UninstallKey" | Out-file -Append -FilePath software_uninstallkey.txt
        #Create an instance of the Registry Object and open the HKLM base key
        $reg=[microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',$computername) 

        #Drill down into the Uninstall key using the OpenSubKey Method
        $regkey=$reg.OpenSubKey($UninstallKey) 

        #Retrieve an array of string that contain all the subkey names
        $subkeys=$regkey.GetSubKeyNames() 

        #Open each Subkey and use GetValue Method to return the required values for each
        foreach($key in $subkeys){
            $thisKey=$UninstallKey+"\\"+$key 
            $thisSubKey=$reg.OpenSubKey($thisKey) 
            $obj = New-Object PSObject
            $obj | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $($thisSubKey.GetValue("DisplayName"))
            $obj | Add-Member -MemberType NoteProperty -Name "DisplayVersion" -Value $($thisSubKey.GetValue("DisplayVersion"))
            $obj | Add-Member -MemberType NoteProperty -Name "InstallLocation" -Value $($thisSubKey.GetValue("InstallLocation"))
            $obj | Add-Member -MemberType NoteProperty -Name "Publisher" -Value $($thisSubKey.GetValue("Publisher"))
            $array += $obj
        } 

        $software_versions += $array | Where-Object { $_.DisplayName } `
        | Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation        
    }
    $software_versions | Export-Csv -Path software_uninstallkey.csv -NoTypeInformation

    # List the directories in the System Drive 
    if (Test-CommandExists Get-ChildItem){
        $software_dirs = ("$sysdrive\Program Files (x86)\","$sysdrive\Program Files\","$sysdrive\")
        ForEach ($dir in $software_dirs){
            if (Test-Path -Path $dir){
                $contents += Get-ChildItem $dir | ?{ $_.PSIsContainer } `
                | Select-Object -Property FullName,Mode,CreationTime,LastAccessTime,LastWriteTime
            }
        }
    } 
    $contents | Export-Csv -Path software_directories.csv -NoTypeInformation

}

Function Get-InstalledHotFixes{
    Get-Wmiobject -class Win32_QuickFixEngineering -namespace "root\cimv2" `
    | Select-Object -Property HotFixID,Description,InstalledOn | Export-Csv -Path .\hotfixes.csv -NoTypeInformation
}

Function Get-InstalledServices{
    Get-WmiObject -Class Win32_Service | Select-Object -Property Name,DisplayName,StartMode,State,ProcessId `
    | Export-Csv .\services.csv -NoTypeInformation
    
}

Function Get-LocalAccounts{
    Get-WmiObject -Class Win32_Useraccount -filter "Localaccount = True" `
    | Select-Object -Property SID,Name,Status,PasswordRequired `
    | Export-CSV -Path .\localaccounts.csv -NoTypeInformation
}

Function Get-LocalGroupAccounts{
    Get-WmiObject -Class Win32_Group -Filter "LocalAccount = True" `
    | Select-Object -Property Caption,SID,Name `
    | Export-CSV -Path .\localgroups.csv -NoTypeInformation
}

Function Get-LocalAccountMembers{

    $gprops = @{'Group Name'='';UserName='';SID=''}
    $gmems_Template = New-Object -TypeName PSObject -Property $gprops

    $groups = Get-WmiObject -Class Win32_Group -Filter "LocalAccount = True"

    $gcombined = $groups | ForEach-Object {
        $gmn = $_.Name

        (Get-WmiObject -Class Win32_Group -Filter "LocalAccount = TRUE and `
        Name= '$gmn'").GetRelated("Win32_Account", "Win32_GroupUser", "", "", `
        "PartComponent", "GroupComponent", $false, $null) | Select-Object -Property Name,SID | ForEach-Object{
            $gmems = $gmems_Template.PSObject.Copy()
            $gmems.'Group Name' = $gmn
            $gmems.UserName = $_.Name
            $gmems.SID = $_.SID
            $gmems
        }
    }

    $gcombined | Export-Csv -Path .\localgroup_members.csv -NoTypeInformation
}

Function Get-WinEventLogs{
    $winlogs = @('Application','Security','System','Windows PowerShell','Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational','Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-WMI-Activity/Operational')
    # Get-WinEvent is available in PSv3
    Get-WinEvent -ListLog $winlogs -ErrorAction SilentlyContinue `
    | Select-Object -Property LogName,MaximumSizeInBytes,FileSize,RecordCount,LogMode `
    | Export-Csv -Path eventlog_settings.csv -NoTypeInformation
}

Function Get-SysAVInfo{

    try{
        $avstate = @{
            "262144" = @{defstatus = "Up to date"; rtstatus = "Disabled"};
            "262160" = @{defstatus = "Out of date"; rtstatus = "Disabled"};
            "266240" = @{defstatus = "Up to date"; rtstatus = "Enabled"};
            "266256" = @{defstatus = "Out of date"; rtstatus = "Enabled"};
            "393216" = @{defstatus = "Up to date"; rtstatus = "Disabled"};
            "393232" = @{defstatus = "Out of date"; rtstatus = "Disabled"};
            "393488" = @{defstatus = "Out of date"; rtstatus = "Disabled"};
            "397312" = @{defstatus = "Up to date"; rtstatus = "Enabled"};
            "397328" = @{defstatus = "Out of date"; rtstatus = "Enabled"};
            "397584" = @{defstatus = "Out of date"; rtstatus = "Enabled"};
            "397568" = @{defstatus = "Up to date"; rtstatus = "Enabled"};
            "393472" = @{defstatus = "Up to date"; rtstatus = "Disabled"};
        }

        $avprodprops = @{'Product Name'='';'Definition Status'='';'Real-Time Protection'='';'Path'=''}
        $avprod_Template = New-Object -TypeName PSObject -Property $avprodprops
        Get-WmiObject -Namespace root/SecurityCenter2 -Class AntivirusProduct -ErrorAction Stop | ForEach-Object {
            $avprod = $avprod_Template.PSObject.Copy()
            $avprod.'Product Name' = $_.displayName
            $avprod.'Definition Status' = $avstate[[string]$_.productState].defstatus
            $avprod.'Real-Time Protection' = $avstate[[string]$_.productState].rtstatus
            $avprod.'Path' = $_.pathToSignedProductExe
        }
        $avprod | Select-Object -Property 'Product Name','Definition Status','Real-Time Protection','Path' `
        | Export-Csv -Path .\antivirus.csv -NoTypeInformation
    }Catch{ Write-Output "Anti-Virus Status Check Failed" }
}

Function Get-InterfaceConfig{

    $data = ForEach ($Adapter in (Get-WmiObject -Class Win32_NetworkAdapter -Filter "NetEnabled='True'")){  
        $Config = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "Index = '$($Adapter.Index)'"
        New-Object PSObject -Property @{
            Interface = $Adapter.NetConnectionID
            IP = $Config.IPAddress
            MAC = $Config.MacAddress
        }
    } 

    $data | Select-Object -Property Interface,IP,MAC `
    | Export-Csv -Path network_interfaces.csv -NoTypeInformation
}

Function Get-RouteConfig{
Get-WmiObject -Class win32_IP4RouteTable | Select-Object -Property InterfaceIndex,Destination,Mask,NextHop,Age `
    | Export-Csv -Path routes.csv -NoTypeInformation
}

Function Get-SharedFolders {
    Get-WmiObject -Class Win32_Share | Select-Object -Property Name,Path,Description,Status,Caption `
    | Export-Csv -Path shares.csv -NoTypeInformation
}

#############################
# Main
#############################

# Output Directory
#############################
Mkdir-Output $outdir

# Report Header
#############################
Prt-ReportHeader
$sysinfo = ''

#############################
# Information Collection
#############################

# Computer Information
#############################
$secName = "Computer Information"
Prt-SectionHeader $secName
Get-SystemInfo

# Timezone Information
#############################
$secName = "Timezone Information"
Prt-SectionHeader $secName
Get-TimezoneInfo

# NTP Configuration Information
#############################
$secName = "NTP Configuration Information"
Prt-SectionHeader $secName
Get-NtpInfo

# Installed Applications
#############################
$secName = "Installed Applications"
Prt-SectionHeader $secName
Get-InstalledSoftware

# Installed Patches
#############################
$secName = "Installed Patches"
Prt-SectionHeader $secName
Get-InstalledHotFixes

# Installed Services
#############################
$secName = "Installed Services"
Prt-SectionHeader $secName
Get-InstalledServices

# Local User Accounts
#############################
$secName = "Local User Accounts"
Prt-SectionHeader $secName
Get-LocalAccounts

# Local Group Accounts
#############################
$secName = "Local Group Accounts"
Prt-SectionHeader $secName
Get-LocalGroupAccounts

# Local Group Memberships
#############################
$secName = "Local Group Memberships"
Prt-SectionHeader $secName
Get-LocalAccountMembers

# Event Log Settings
#############################
$secName = "Event Log Settings"
Prt-SectionHeader $secName
Get-WinEventLogs

# Anti-Virus Status 
#############################
$secName = "Anti-Virus Status"
Prt-SectionHeader $secName
Get-SysAVInfo

# Network Interfaces
#############################
$secName = "Network Interfaces"
Prt-SectionHeader $secName
Get-InterfaceConfig

# Network Routes
#############################
$secName = "Network Routes"
Prt-SectionHeader $secName
Get-RouteConfig

# File Shares
#############################
$secName = "File Shares"
Prt-SectionHeader $secName
Get-SharedFolders

# Report Footer
#############################
Prt-ReportFooter
if($cutsec_footer){ Prt-CutSec-ReportFooter }
