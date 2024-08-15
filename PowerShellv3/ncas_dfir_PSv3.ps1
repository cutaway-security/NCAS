<#
	ncas_dfir.ps1 - NERC CIP Assessment Script for Windows system
        with PowerShell greater than 3. This script will collect 
        data from the system using default Cmdlets or using the
        Get-CmdInstance (requires PSv3) and output to the screen. 
        This script collects static and volatile information.
    Author: Don C. Weber (@cutaway)
    Date:   May 25, 2022
#>

<#
	License: 
	Copyright (c) 2022, Cutaway Security, Inc. <dev [@] cutawaysecurity.com>
	
	ncas_dfir.ps1 is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	
	ncas_dfir.ps1 is distributed in the hope that it will be useful,
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
$script_name         = 'ncas_dfir'
$script_version      = '1.0.4'
$start_time_readable = Get-Date -Format "dddd MM/dd/yyyy HH:mm:ss K"
$computername        = $env:ComputerName
$sysdrive            = $env:SystemDrive

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

    $stop_time_readable = Get-Date -Format "dddd MM/dd/yyyy HH:mm:ss K"

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
    if (Test-CommandExists Get-ComputerInfo){
        $sysdata = Get-ComputerInfo -Property WindowsProductName,OsVersion,WindowsCurrentVersion,WindowsVersion,OsArchitecture,CsWorkgroup
    }else{
        if ($sysinfo -eq ''){$sysinfo = systeminfo}
        $sysdata = $sysinfo | Select-String -Pattern '^OS Version','^OS Name','^System Type','^Domain'  
    }
    $sysdata
    
    Write-Output "`nCommand Results: systeminfo`n"
    $sdata = systeminfo
    $sdata
}

Function Get-TimezoneInfo{
    if (Test-CommandExists Get-TimeZone){
        $timezone = Get-TimeZone
    }else{
        $timezone = Get-CimInstance -ClassName Win32_TimeZone | Select-Object -Property Caption,Bias,StandardName,DaylightName,DaylightBias  
    }
    $timezone
}

Function Get-NtpInfo{
    # Reference: https://docs.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings
    $ntptype = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\W32Time\Parameters").Type
    Write-Output "Server syncronization setting: $ntptype"
    # NTP Server settings
    $ntpservers = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\w32time\Parameters" -Name "NtpServer").NtpServer
    Write-Output "NTP Server Sources: $ntpservers"
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
        Write-Output "Processing UninstallKey $UninstallKey"
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
        | Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation

        $software_versions | Format-Table -AutoSize | Out-String -Width 4096
    }

    # List the directories in the System Drive 
    if (Test-CommandExists Get-ChildItem){
        $software_dirs = ("$sysdrive\Program Files (x86)\","$sysdrive\Program Files\","$sysdrive\")
        ForEach ($dir in $software_dirs){
            if (Test-Path -Path $dir){
                Write-Output "List of Program Directories in $dir"
                Get-ChildItem -Directory $dir | Format-Table -Property FullName,Mode,CreationTime,LastAccessTime,LastWriteTime -AutoSize | Out-String -Width 4096
            }
        }
    }
    
    # List the directories in logical drives that are not the System Drive 
    if (Test-CommandExists Get-ChildItem -and Test-CommandExists Get-WmiObject){
        $logical_drive = ((Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 -and $_.DeviceID -ne $sysdrive }).DeviceID)
        ForEach ($dir in $logical_drive){
            if (Test-Path -Path $dir){
                Write-Output "List of Directories in $dir"
                Get-ChildItem -Directory $dir | Format-Table -Property FullName,Mode,CreationTime,LastAccessTime,LastWriteTime -AutoSize | Out-String -Width 4096
            }
        }
    }
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

    $gprops = @{'Group Name'='';UserName='';SID=''}
    $gmems_Template = New-Object -TypeName PSObject -Property $gprops

    if ((Test-CommandExists Get-LocalGroup) -and (Test-CommandExists Get-LocalGroupMamber)){
        $groups = Get-LocalGroup

        $gcombined = $groups | ForEach-Object {
            $gmn = $_.Name
            Get-LocalGroupMember $gmn | ForEach-Object {
                $gmems = $gmems_Template.PSObject.Copy()
                $gmems.'Group Name' = $gmn
                $gmems.UserName = $_.Name
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
                $gmems.UserName = $_.Name
                $gmems.SID = $_.SID
                $gmems
            }
        }
    }

    $gcombined | Format-Table -Property 'Group Name',UserName,SID -AutoSize | Out-String -Width 4096
}

Function Get-WinEventLogs{
    $winlogs = @('Application','Security','System','Windows PowerShell','Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational','Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-WMI-Activity/Operational')
    # Get-WinEvent is available in PSv3
    Get-WinEvent -ListLog $winlogs -ErrorAction SilentlyContinue | Format-Table LogName,MaximumSizeInBytes,FileSize,RecordCount,LogMode -AutoSize | Out-String -Width 4096
}

Function Get-SysAVInfo{
    if (Test-CommandExists Get-MPComputerStatus){
        Write-Output "# Windows Defender Status"
        $defender_status = Get-MPComputerStatus -ErrorAction SilentlyContinue
        if ($defender_status){
            $defender_status
        }else{
            Write-Output "No response, possibly disabled."
        }
    }

    try{
        # Define AV Product Bit Flags    
        [Flags()] enum ProductState 
        {
            Off         = 0x0000
            On          = 0x1000
            Snoozed     = 0x2000
            Expired     = 0x3000
        }

        [Flags()] enum SignatureStatus
        {
            UpToDate     = 0x00
            OutOfDate    = 0x10
        }

        [Flags()] enum ProductOwner
        {
            NonMs        = 0x000
            Windows      = 0x100
        }

        # Define AV Product Bit Masks    
        [Flags()] enum ProductFlags
        {
            SignatureStatus = 0x00F0
            ProductOwner    = 0x0F00
            ProductState    = 0xF000
        }

        $avprodprops = @{'Product Name'='';'Definition Status'='';'Real-Time Protection'='';'ProdOwner'='';'ProdExePath'='';'ReportExePath'=''}
        $avprod_Template = New-Object -TypeName PSObject -Property $avprodprops
        Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction Stop | ForEach-Object {
            [UInt32]$state = $_.productState
            $avprod = $avprod_Template.PSObject.Copy()
            $avprod.'Product Name' = $_.displayName
            $avprod.'Definition Status' = [SignatureStatus]($state -band [ProductFlags]::SignatureStatus)
            $avprod.'Real-Time Protection' = [ProductState]($state -band [ProductFlags]::ProductState)
            $avprod.'ProdOwner' = [ProductOwner]($state -band [ProductFlags]::ProductOwner)
            $avprod.'ProdExePath' = $_.pathToSignedProductExe
            $avprod.'ReportExePath' = $_.pathToSignedReportingExe
        }

        Write-Output "# Other Anti-Virus Status"
        $avprod | Format-Table -Property 'Product Name','Definition Status','Real-Time Protection','ProdOwner','ProdExePath','ReportExePath' -AutoSize | Out-String -Width 4096
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

Function Get-RouteConfig{

    if (Test-CommandExists Get-NetRoute){
        Get-NetRoute | Format-Table -Property InterfaceIndex,InterfaceAlias,DestinationPrefix,NextHop,State,AddressFamily
    } else {
        Get-CimInstance -ClassName win32_IP4RouteTable | Format-Table -Property InterfaceIndex,Destination,Mask,NextHop,Age
    }
}

Function Get-SharedFolders {
    if (Test-CommandExists Get-SmbShare){
        Get-SmbShare | Format-Table -Property Name,Description,Path,ShareType,ShareState,CurrentUsers,EncryptData -AutoSize | Out-String -Width 4096
        if (Test-CommandExists Get-FileShare){
            Get-FileShare -ErrorAction SilentlyContinue | Format-Table -Property Name,UniqueId,Description,EncryptData,VolumeRelativePath,PassThroughClass
        }
    }else{
        Get-CimInstance -ClassName Win32_Share | Format-Table -Property Name,Description,Path,Status -AutoSize | Out-String -Width 4096
    }
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
# Volatile Information Collection Functions
#############################
Function Get-EnvInfo{
    # Get all of the current ENV parameters
    Get-ChildItem env: | Format-List -Property *
}

Function Get-TCPServicesInfo{
    # Make a lookup table by process ID 
    $Processes = @{}
    if (($global:admin_user) -and ([int]$global:ps_version -gt 2)){
        Get-Process -IncludeUserName | ForEach-Object { $Processes[$_.Id] = $_ }
    } else {
        Get-Process | ForEach-Object { $Processes[$_.Id] = $_ }

    }

    if (Test-CommandExists Get-NetTCPConnection){
        # Query Listening TCP Daemons
        $tcplisteners = Get-NetTCPConnection 
    }else{
        # Query Listening TCP 
        try{
            $tcplisteners = Get-CimInstance -Namespace ROOT\StandardCIMV2 -Class MSFT_NetTCPConnection -ErrorAction Stop 
        } Catch {
            netstat -naob -p TCP
            return
        }
    }

    if (($global:admin_user) -and ([int]$global:ps_version -gt 2)){
        $tcpservers = $tcplisteners | 
            Where-Object { $_.State -eq "Listen" -and $_.LocalAddress -ne "127.0.0.1" } |
            Select-Object LocalAddress,
                LocalPort,
                @{Name="PID";         Expression={ $_.OwningProcess }},
                @{Name="ProcessName"; Expression={ $inpid = [int]($_.OwningProcess); $Processes[$inpid].Name }}, 
                @{Name="UserName"; Expression={ $inpid = [int]($_.OwningProcess); $Processes[$inpid].UserName }},
                @{Name="Path"; Expression={ $inpid = [int]($_.OwningProcess); $Processes[$inpid].Path }}, 
                @{Name="CommandLine"; Expression={ $inpid = [int]($_.OwningProcess); (Get-CimInstance -ClassName Win32_Process | Where-Object {$_.ProcessId -eq $inpid}).CommandLine }} |
            Sort-Object -Property LocalPort, LocalAddress

        $tcpservers | Format-Table -Property ProcessName,PID,UserName,LocalAddress,LocalPort,Path,CommandLine -AutoSize | Out-String -Width 4096

    } else {
        $tcpservers = $tcplisteners | 
            Where-Object { $_.State -eq "Listen" -and $_.LocalAddress -ne "127.0.0.1" } |
            Select-Object LocalAddress,
                LocalPort,
                @{Name="PID";         Expression={ $_.OwningProcess }},
                @{Name="ProcessName"; Expression={ $inpid = [int]($_.OwningProcess); (Get-CimInstance -ClassName Win32_Process | Where-Object {($_.ProcessId -eq $inpid)}).Name }} |
            Sort-Object -Property LocalPort, LocalAddress

        $tcpservers | Format-Table -Property ProcessName,PID,LocalAddress,LocalPort -AutoSize | Out-String -Width 4096
    }
}

Function Get-UDPServicesInfo{
    # Make a lookup table by process ID
    $Processes = @{}
    if (($global:admin_user) -and ([int]$global:ps_version -gt 2)){
        Get-Process -IncludeUserName | ForEach-Object { $Processes[$_.Id] = $_ }
    } else {
        Get-Process | ForEach-Object { $Processes[$_.Id] = $_ }

    }

    if (Test-CommandExists Get-NetUDPEndpoint){
        # Query Listening UDP Daemons
        $udplisteners = Get-NetUDPEndpoint 
    }else{
        # Query Listening UDP Daemons
        try{
            $udplisteners = Get-CimInstance -Namespace ROOT\StandardCIMV2 -Class MSFT_NetUDPEndpoint -ErrorAction SilentlyContinue -ErrorAction Stop 
        } Catch {
            netstat -naob -p UDP
            return
        }
    }

    # Query Listening UDP Daemons
    if (($global:admin_user) -and ([int]$global:ps_version -gt 2)){
        $udpservers = $udplisteners | 
            Where-Object { $_.LocalAddress -ne "127.0.0.1" } |
            Select-Object LocalAddress,
                LocalPort,
                @{Name="PID";         Expression={ $_.OwningProcess }},
                @{Name="ProcessName"; Expression={ $inpid = [int]($_.OwningProcess); $Processes[$inpid].Name }}, 
                @{Name="UserName"; Expression={ $inpid = [int]($_.OwningProcess); $Processes[$inpid].UserName }},
                @{Name="Path"; Expression={ $inpid = [int]($_.OwningProcess); $Processes[$inpid].Path }},  
                @{Name="CommandLine"; Expression={ $inpid = [int]($_.OwningProcess); (Get-CimInstance -ClassName Win32_Process | Where-Object {$_.ProcessId -eq $inpid}).CommandLine }} |
            Sort-Object -Property LocalPort, LocalAddress 

        $udpservers | Format-Table -Property ProcessName,PID,UserName,LocalAddress,LocalPort,Path,CommandLine -AutoSize | Out-String -Width 4096
        
    } else {
        $udpservers = $udplisteners | 
            Where-Object { $_.LocalAddress -ne "127.0.0.1" } |
            Select-Object LocalAddress,
                LocalPort,
                @{Name="PID";         Expression={ $_.OwningProcess }},
                @{Name="ProcessName"; Expression={ $inpid = [int]($_.OwningProcess); (Get-CimInstance -ClassName Win32_Process | Where-Object {($_.ProcessId -eq $inpid)}).Name }} |
            Sort-Object -Property LocalPort, LocalAddress 

        $udpservers | Format-Table -Property ProcessName,PID,LocalAddress,LocalPort -AutoSize | Out-String -Width 4096

    }
}

Function Get-ProcessMemory{
    try{
        Get-Process | foreach-object {
            Get-Process -IncludeUserName -name $_.ProcessName -PipelineVariable pv -ErrorAction Stop |
            Measure-Object Workingset -sum -average |
            Select-object Count,Name,Id,
            @{Name="UserName";Expression = {$pv.UserName}},
            @{Name="Path";Expression = {$pv.Path}},
            @{Name="CmdLine";Expression = {(Get-CimInstance -ClassName Win32_Process | Where-Object {$_.ProcessId -eq $pv.Id}).CommandLine }},
            @{Name="SumMB";Expression = {[math]::round($_.Sum/1MB,2)}},
            @{Name="AvgMB";Expression = {[math]::round($_.Average/1MB,2)}},
            @{Name="VirtualMemorySize";Expression = {$pv.VirtualMemorySize}},
            @{Name="VirtualMemorySize64";Expression = {$pv.VirtualMemorySize64}}
        } | Format-Table -AutoSize | Out-String -Width 4096
    } Catch {        
        Get-Process | foreach-object {
            Get-Process -name $_.ProcessName -PipelineVariable pv -ErrorAction Stop |
            Measure-Object Workingset -sum -average |
            Select-object Count,Name,Id,
            @{Name="Path";Expression = {$pv.Path}},
            @{Name="CmdLine";Expression = {(Get-CimInstance -ClassName Win32_Process | Where-Object {$_.ProcessId -eq $pv.Id}).CommandLine }},
            @{Name="SumMB";Expression = {[math]::round($pv.Sum/1MB,2)}},
            @{Name="AvgMB";Expression = {[math]::round($_.Average/1MB,2)}},
            @{Name="VirtualMemorySize";Expression = {$pv.VirtualMemorySize}},
            @{Name="VirtualMemorySize64";Expression = {$pv.VirtualMemorySize64}}
        } | Format-Table -AutoSize | Out-String -Width 4096
    }
}

Function Get-USBDevices{
    # Get Currently Connected USB Devices - HID and Mass Storage
    Write-Output "`nConnected HID and Mass Storage USB Devices:"
    Get-CimInstance -ClassName Win32_PnpEntity -ErrorAction SilentlyContinue | Where-Object {($_.DeviceID -like "*hid*") -or ($_.Description -like "*mass*")}| Select-Object -Property DeviceID,Name,Description,Manufacturer,PNPClass | Format-List -Property *

    # Get History of Connected USB Devices - Mass Storage
    Write-Output "`History Mass Storage USB Devices:"
    try {
        Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*' -ErrorAction Stop | Select FriendlyName,@{Name="SerialNumber";Expression={($_.PSChildName)}},@{Name="CompatibleIDs";Expression={($_.CompatibleIDs)}} | Format-List -Property *
    } Catch {
        Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB\*\*' -ErrorAction SilentlyContinue | Where-Object {$_.DeviceDesc -like "*mass*"} | Select @{Name="DeviceDesc";Expression={($_.DeviceDesc).split(";")[1]}},@{Name="SerialNumber";Expression={($_.PSChildName)}},@{Name="HardwareID";Expression={($_.HardwareID)[0]}} | Format-List -Property *
    }

    # Get History of Connected USB Devices - HID
    Write-Output "`History HID USB Devices:"
    Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\HID\*\*' -ErrorAction SilentlyContinue | Select @{Name="DeviceDesc";Expression={($_.DeviceDesc).split(";")[1]}},@{Name="SerialNumber";Expression={($_.PSChildName)}} | Format-Table -AutoSize | Out-String -Width 4096
}

Function Get-SchedTasks{
    # Get a list of the currently scheduled tasks
    if (Test-CommandExists Get-ScheduledTask){
        Get-ScheduledTask | Format-Table -Property TaskName,TaskPath,State,Triggers,Date,Author -AutoSize | Out-String -Width 4096
    } else {
        schtasks.exe
    }
}

Function Get-AuthEvents {
    <#
        This function is a modification of the script described and provided here:
        Source: https://adamtheautomator.com/user-logon-event-id/

        This script finds all PowerShell last logon, logoff and total active session times of all users on all computers specified. For this script
        to function as expected, the advanced AD policies; Audit Logon, Audit Logoff and Audit Other Logon/Logoff Events must be
        enabled and targeted to the appropriate computers via GPO or local policy.
    #>

    BEGIN {
        $WarningPreference = 'SilentlyContinue'
        $ErrorActionPreference = 'Stop'
    }

    PROCESS{
        try{
            #region Defie all of the events to indicate session start or top
            $sessionEvents = @(
                @{ 'Label' = 'Logon'; 'EventType' = 'SessionStart'; 'LogName' = 'Security'; 'ID' = 4624 } ## Advanced Audit Policy --> Audit Logon
                @{ 'Label' = 'Logoff'; 'EventType' = 'SessionStop'; 'LogName' = 'Security'; 'ID' = 4647 } ## Advanced Audit Policy --> Audit Logoff
                @{ 'Label' = 'Startup'; 'EventType' = 'SessionStop'; 'LogName' = 'System'; 'ID' = 6005 }
                @{ 'Label' = 'RdpSessionReconnect'; 'EventType' = 'SessionStart'; 'LogName' = 'Security'; 'ID' = 4778 } ## Advanced Audit Policy --> Audit Other Logon/Logoff Events
                @{ 'Label' = 'RdpSessionDisconnect'; 'EventType' = 'SessionStop'; 'LogName' = 'Security'; 'ID' = 4779 } ## Advanced Audit Policy --> Audit Other Logon/Logoff Events
                @{ 'Label' = 'Locked'; 'EventType' = 'SessionStop'; 'LogName' = 'Security'; 'ID' = 4800 } ## Advanced Audit Policy --> Audit Other Logon/Logoff Events
                @{ 'Label' = 'Unlocked'; 'EventType' = 'SessionStart'; 'LogName' = 'Security'; 'ID' = 4801 } ## Advanced Audit Policy --> Audit Other Logon/Logoff Events
            )

            ## All of the IDs that designate when user activity starts
            $sessionStartIds = ($sessionEvents | where { $_.EventType -eq 'SessionStart' }).ID
            ## All of the IDs that designate when user activity stops
            $sessionStopIds = ($sessionEvents | where { $_.EventType -eq 'SessionStop' }).ID
            #endregion

            ## Define all of the log names we'll be querying
            $logNames = ($sessionEvents.LogName | select -Unique)
            ## Grab all of the interesting IDs we'll be looking for
            $ids = $sessionEvents.Id
                
            ## Build the insane XPath query for the security event log in order to query PowerShell last logon events and others as fast as possible
            $logonXPath = "Event[System[EventID=4624]] and Event[EventData[Data[@Name='TargetDomainName'] != 'Window Manager']] and Event[EventData[Data[@Name='TargetDomainName'] != 'NT AUTHORITY']] and (Event[EventData[Data[@Name='LogonType'] = '2']] or Event[EventData[Data[@Name='LogonType'] = '10']])"
            $otherXpath = 'Event[System[({0})]]' -f "EventID=$(($ids.where({ $_ -ne '4624' })) -join ' or EventID=')"
            $xPath = '({0}) or ({1})' -f $logonXPath, $otherXpath


            ## Query each computer's event logs using the Xpath filter
            $events = Get-WinEvent -LogName $logNames -FilterXPath $xPath
            Write-Verbose -Message "Found [$($events.Count)] events to look through"

            $evts = @()

            ## Set up the output object
            $output = [ordered]@{
                'ComputerName'          = $env:COMPUTERNAME
                'Username'              = $null
                'StartTime'             = $null
                'StartAction'           = $null
                'StopTime'              = $null
                'StopAction'            = $null
                'Session Active (Days)' = $null
                'Session Active (Min)'  = $null
                'LogonType'             = $null
            }

            ## Need current users because if no stop time, they're still probably logged in
            $getGimInstanceParams = @{
                ClassName = 'Win32_ComputerSystem'
            }
            if ($computer -ne $Env:COMPUTERNAME) {
                $getGimInstanceParams.ComputerName = $computer
            }
            $loggedInUsers = Get-CimInstance @getGimInstanceParams | Select-Object -ExpandProperty UserName | foreach { $_.split('\')[1] }
                
            ## Find all user start activity events and begin parsing
            $events.where({ $_.Id -in $sessionStartIds }).foreach({
                    try {
                        $logonEvtId = $_.Id
                        $output.StartAction = $sessionEvents.where({ $_.ID -eq $logonEvtId }).Label
                        $xEvt = [xml]$_.ToXml()

                        ## Figure out the login session ID
                        $output.Username = ($xEvt.Event.EventData.Data | where { $_.Name -eq 'TargetUserName' }).'#text'
                        $logonId = ($xEvt.Event.EventData.Data | where { $_.Name -eq 'TargetLogonId' }).'#text'
                        if (-not $logonId) {
                            $logonId = ($xEvt.Event.EventData.Data | where { $_.Name -eq 'LogonId' }).'#text'
                        }
                        $output.LogonType = ($xEvt.Event.EventData.Data | where { $_.Name -eq 'LogonType'}).'#text'
                        $output.StartTime = $_.TimeCreated

                        Write-Verbose -Message "New session start event found: event ID [$($logonEvtId)] username [$($output.Username)] logonID [$($logonId)] time [$($output.StartTime)]"
                        ## Try to match up the user activity end event with the start event we're processing
                        if (-not ($sessionEndEvent = $Events.where({ ## If a user activity end event could not be found, assume the user is still logged on
                                        $_.TimeCreated -gt $output.StartTime -and
                                        $_.ID -in $sessionStopIds -and
                                        (([xml]$_.ToXml()).Event.EventData.Data | where { $_.Name -eq 'TargetLogonId' }).'#text' -eq $logonId
                                    })) | select -last 1) {
                            if ($output.UserName -in $loggedInUsers) {
                                $output.StopTime = Get-Date
                                $output.StopAction = 'Still logged in'
                            } else {
                                throw "Could not find a session end event for logon ID [$($logonId)]."
                            }
                        } else {
                            ## Capture the user activity end time
                            $output.StopTime = $sessionEndEvent.TimeCreated
                            Write-Verbose -Message "Session stop ID is [$($sessionEndEvent.Id)]"
                            $output.StopAction = $sessionEvents.where({ $_.ID -eq $sessionEndEvent.Id }).Label
                        }

                        $sessionTimespan = New-TimeSpan -Start $output.StartTime -End $output.StopTime
                        $output.'Session Active (Days)' = [math]::Round($sessionTimespan.TotalDays, 2)
                        $output.'Session Active (Min)'  = [math]::Round($sessionTimespan.TotalMinutes, 2)
                        
                        $evts += [pscustomobject]$output
                    } catch {
                        Write-Warning -Message $_.Exception.Message
                    }
            })
        }Catch{ Write-Output "Could not retrieve Auth Eventlogs. Grab the full logs manually."}
    }
    END {$evts | Format-Table -AutoSize | Out-String -Width 4096}
}

Function Get-PreFetch{
    $prefetch_dir = ("$sysdrive\Windows\Prefetch")
    if (Test-CommandExists Get-ChildItem){
        ForEach ($dir in $prefetch_dir){
            if (Test-Path -Path $dir){
                Write-Output "List of Prefetch Items in $dir"
                Get-ChildItem $dir | Format-Table -Property Name,LastWriteTime,LastAccessTime,Mode
            }
        }
    }   
}

#############################
# Main
#############################

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

# Common Vulnerability Checks
#############################
if (($global:admin_user) -and ([int]$global:ps_version -gt 2)){
    $secName = "Common Vulnerability Checks"
    Prt-SectionHeader $secName
    Get-VulnCheck
}

# File Shares
#############################
$secName = "File Shares"
Prt-SectionHeader $secName
Get-SharedFolders

#############################
# Volatile Information Collection 
#############################

# Environmental Variables
#############################
$secName = "Environmental Variables"
Prt-SectionHeader $secName
Get-EnvInfo

# Network TCP Connections
#############################
$secName = "Network TCP Connections"
Prt-SectionHeader $secName
Get-TCPServicesInfo

# Network UDP Connections
#############################
$secName = "Network UDP Connections"
Prt-SectionHeader $secName
Get-UDPServicesInfo

# Process Memory Usage
#############################
if (($global:admin_user) -and ([int]$global:ps_version -gt 2)){
    $secName = "Process Memory Usage"
    Prt-SectionHeader $secName
    Get-ProcessMemory
}

# Scheduled Tasks
#############################
if (($global:admin_user) -and ([int]$global:ps_version -gt 2)){
    $secName = "Scheduled Tasks"
    Prt-SectionHeader $secName
    Get-SchedTasks
}

# USB Device History
#############################
if (($global:admin_user) -and ([int]$global:ps_version -gt 2)){
    $secName = "USB Device History"
    Prt-SectionHeader $secName
    Get-USBDevices
}

# Authentication Events
#############################
if (($global:admin_user) -and ([int]$global:ps_version -gt 2)){
    $secName = "Authentication Events"
    Prt-SectionHeader $secName
    Get-AuthEvents
}

# Prefetch Items
#############################
if (($global:admin_user) -and ([int]$global:ps_version -gt 2)){
    $secName = "Prefetch Items"
    Prt-SectionHeader $secName
    Get-PreFetch
}

# Report Footer
#############################
Prt-ReportFooter
if($cutsec_footer){ Prt-CutSec-ReportFooter }
