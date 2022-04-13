<#
	ncas_collector.ps1 - NERC CIP Assessment Script for Windows system
        with PowerShell greater than 3. This script will collect 
        data from the system using default Cmdlets or using the
        Get-CmdInstance (requires PSv3) and output to the screen. 
    Author: Don C. Weber (@cutaway)
    Date:   April 12, 2022
#>

<#
	License: 
	Copyright (c) 2022, Cutaway Security, Inc. <dev [@] cutawaysecurity.com>
	
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
$global:admin_user  = $false # Disable some checks if not running as an Administrator
$global:ps_version  = $PSVersionTable.PSVersion.Major # Get major version to ensure at least PSv3

#############################
# Set up document header information
#############################
$script_name         = 'ncas_collector'
$script_version      = '1.0'
$start_time          = Get-Date -format yyyyMMddHHmmssff
$start_time_readable = Get-Date -Format "dddd MM/dd/yyyy HH:mm"
$computername        = $env:ComputerName
$runname             = $company_sh + '_' + $start_time

#############################
# Print Functions
#############################

function Prt-SectionHeader{

	Param(
		# Enable means to change the setting to the default / insecure state.
		$SectionName = 'Section Name'
	)

    Write-Output "`n#############################"
    Write-Output "# $SectionName"
    Write-Output "#############################"
}

function Prt-ReportHeader{

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

function Prt-ReportFooter{

    $stop_time_readable = Get-Date -Format "dddd MM/dd/yyyy HH:mm"

    Write-Output "`n#############################"
    Write-Output "# $script_name completed"
    Write-Output "# Stop Time: $stop_time_readable"
    Write-Output "#############################`n"

}

function Prt-CutSec-ReportFooter{

    Write-Output "`n#############################"
    Write-Output "# NERC CIP Audit Script: $script_name $script_version"
    Write-Output "# Brought to you by Cutaway Security, LLC"
    Write-Output "# For assessment and auditing help, contact info [@] cutawaysecurity.com"
    Write-Output "# For script help, contact dev [@] cutawaysecurity.com"
    Write-Output "#############################`n"

}

#############################
# Test Cmdlet Exists, to help default to Get-CimInstance
#############################
Function Test-CommandExists{
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'stop'
    try {if(Get-Command $command){RETURN $true}}
    Catch {RETURN $false}
    Finally {$ErrorActionPreference=$oldPreference}
} 

# Check for Administrator Role 
####################
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
# Test Cmdlet Exists, to help default to Get-CimInstance
#############################
Function Get-SystemInfo{
    if (Test-CommandExists Get-ComputerInfo){
        $sysdata = Get-ComputerInfo -Property WindowsProductName,OsVersion,WindowsCurrentVersion,WindowsVersion,OsArchitecture,CsWorkgroup
    }else{
        if ($sysinfo -eq ''){$sysinfo = systeminfo}
        $sysdata = $sysinfo | Select-String -Pattern '^OS Version','^OS Name','^System Type','^Domain'  
    }
    $sysdata
}

Function Get-InstalledSoftware{
    $array = @()

    #Define the variable to hold the location of Currently Installed Programs
    $UninstallKey="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"

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

    $software_versions = $array | Where-Object { $_.DisplayName } `
    | select DisplayName, DisplayVersion, Publisher, InstallLocation

    $software_versions | Format-Table -AutoSize | Out-String -Width 4096
}

Function Get-InstalledHotFixes{
    if (Test-CommandExists Get-HotFix){
        Get-HotFix | Format-Table -Property HotFixID,Description,InstalledOn -AutoSize | Out-String -Width 4096
    }else{
        Get-CimInstance -ClassName Win32_QuickFixEngineering | Format-Table -Property HotFixID,Description,InstalledOn -AutoSize | Out-String -Width 4096
    }
}

Function Get-InstalledServices{
    Get-CimInstance -ClassName win32_service  | Format-Table Name, Startname, Startmode, Pathname -AutoSize | Out-String -Width 4096
}

Function Get-LocalAccounts{
    if (Test-CommandExists Get-LocalUser){
        Get-LocalUser | Format-Table -Property Name,SID,Enabled,PasswordRequired,PasswordExpires -AutoSize | Out-String -Width 4096
    }else{
        Get-CimInstance -ClassName Win32_UserAccount | Format-Table -Property Name,SID,Disabled,PasswordRequired,PasswordExpires -AutoSize | Out-String -Width 4096
    }
}

Function Get-LocalGroupAccounts{
    if (Test-CommandExists Get-LocalUser){
        Get-LocalGroup | Format-Table -Property Name,SID -AutoSize | Out-String -Width 4096
    }else{
        Get-CimInstance -ClassName Win32_Group | Format-Table -Property Name,SID -AutoSize | Out-String -Width 4096
    }
}

Function Get-LocalAccountMembers{

    $gprops = @{'Group Name'='';Name='';SID=''}
    $gmems_Template = New-Object -TypeName PSObject -Property $gprops

    if ((Test-CommandExists Get-LocalGroup) -and (Test-CommandExists Get-LocalGroupMamber)){
        $groups = Get-LocalGroup

        $gcombined = $groups | ForEach-Object {
            $gmn = $_.Name
            Get-LocalGroupMember $gmn | ForEach-Object {
                $gmems = $gmems_Template.PSObject.Copy()
                $gmems.'Group Name' = $gmn
                $gmems.Name = $_.Name
                $gmems.SID = $_.SID
                $gmems
            }
        }
    }else{
        $groups = Get-CimInstance Win32_group -Filter "LocalAccount=TRUE"

        $gcombined = $groups | ForEach-Object {
            $gmn = $_.Name
            Get-CimInstance win32_group -Filter "LocalAccount=TRUE and Name='$gmn'" | Get-CimAssociatedInstance -Association Win32_GroupUser | ForEach-Object {
                $gmems = $gmems_Template.PSObject.Copy()
                $gmems.'Group Name' = $gmn
                $gmems.Name = $_.Name
                $gmems.SID = $_.SID
                $gmems
            }
        }
    }

    $gcombined | Format-Table -Property 'Group Name',Name,SID -AutoSize | Out-String -Width 4096
}

Function Get-WinEventLogs{
    $winlogs = @('Application','Security','System','Windows PowerShell','Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational','Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-WMI-Activity/Operational')
    # Get-WinEvent is available in PSv3
    Get-WinEvent -ListLog $winlogs -ErrorAction SilentlyContinue | Format-Table LogName,MaximumSizeInBytes,FileSize,RecordCount,LogMode -AutoSize | Out-String -Width 4096
}

Function Get-SysAVInfo{
    if (Test-CommandExists Get-MPComputerStatus){
        Write-Output "# Windows Defender Status"
        Get-MPComputerStatus
    }

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
        Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction Stop | ForEach-Object {
            $avprod = $avprod_Template.PSObject.Copy()
            $avprod.'Product Name' = $_.displayName
            $avprod.'Definition Status' = $avstate[[string]$_.productState].defstatus
            $avprod.'Real-Time Protection' = $avstate[[string]$_.productState].rtstatus
            $avprod.'Path' = $_.pathToSignedProductExe
        }
        Write-Output "# Other Anti-Virus Status"
        $avprod | Format-Table -Property 'Product Name','Definition Status','Real-Time Protection','Path' -AutoSize | Out-String -Width 4096
    }Catch{ Write-Output "Other Anti-Virus Status Check Failed" }
}

Function Get-InterfaceConfig{
    if ((Test-CommandExists Get-LocalGroup) -and (Test-CommandExists Get-LocalGroupMember)){
        $data = @()
        $netinfo = Get-NetIPConfiguration -Detailed 
        foreach ( $nic in $netinfo) { 
            foreach ($ip in $nic) { 
                $data += [pscustomobject] @{
                    Interface=$nic.InterfaceAlias;  
                    IP=$ip.IPv4Address,($ip.IPv6LinkLocalAddress.IPAddress -Split '%')[0]
                    MAC=$nic.NetAdapter.MACAddress;
                }
            }
        } 
    }else{
        $data = ForEach ($Adapter in (Get-CimInstance -ClassName Win32_NetworkAdapter -Filter "NetEnabled='True'")){  
            $Config = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "Index = '$($Adapter.Index)'"
            New-Object PSObject -Property @{
                Interface = $Adapter.NetConnectionID
                IP = $Config.IPAddress
                MAC = $Config.MacAddress
            }
        } 
    }
    $data | Format-Table -Property Interface,IP,MAC -AutoSize | Out-String -Width 4096
}

Function Get-VulnCheck{
    # Check for NetBIOS configuration. Requires PSv3
    if (Test-CommandExists Get-NetAdapter){
        Write-Output "NetBIOS Configurations:"
        (Get-NetAdapter -Physical | Where-Object {$_.Name -NotLike '*Loopback*' -And $_.Status -eq 'Up'}) | ForEach-Object -Process {
            $if_guid = $_.InterfaceGuid; 
            $if_nb_setting = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\TCPIP_$if_guid).NetbiosOptions; 
            $if_name = $_.Name;
            if ($if_nb_setting){$nb_config = 'Enabled'}else{$nb_config = 'Disabled'}
            Write-Output "Interface $if_name : NetBIOS $nb_config [$if_nb_setting]";
        }
    }

    # Check if SMBv1 is Enabled
    if (Test-CommandExists Get-WindowsOptionalFeature){
        $smb_state = (Get-WindowsOptionalFeature -Online -FeatureName smb1protocol).State
        Write-Output "`nSMBv1 is currently: $smb_state"
    }

    # Check SMB Configuration
    if (Test-CommandExists Get-SmbServerConfiguration){
        Write-Output "`nSMB Configurations:"
        Get-SmbServerConfiguration | Format-List -Property EncryptData,EnableSMB1Protocol,EnableSMB2Protocol,EnableSecuritySignature
    }
}

#############################
# Main
#############################

# Report Header
#############################
Prt-ReportHeader
$sysinfo = ''

# Computer Information
#############################
$secName = "Computer Information"
Prt-SectionHeader $secName
Get-SystemInfo

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

# Common Vulnerability Checks
#############################
if (($global:admin_user) -and ([int]$global:ps_version -gt 2)){
    $secName = "Common Vulnerability Checks"
    Prt-SectionHeader $secName
    Get-VulnCheck
}

# Report Footer
#############################
Prt-ReportFooter
if($cutsec_footer){ Prt-CutSec-ReportFooter }
