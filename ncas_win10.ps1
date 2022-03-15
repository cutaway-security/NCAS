<#
	ncas_win10.ps1 - NERC CIP Audit Script for Windows 10. This script 
                     will collect data from the system and generate a
                     text and HTML report file, and provide individual
                     output files.
    Author: Don C. Weber (@cutaway)
    Date:   March 15, 2022
#>

<#
	License: 
	Copyright (c) 2022, Cutaway Security, Inc. <dev [@] cutawaysecurity.com>
	
	sawh.ps1 is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	
	sawh.ps1 is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
	Point Of Contact:    Don C. Weber <dev [@] cutawaysecurity.com>
#>

#############################
# Set up document header information
#############################
$script_name         = 'ncas_win10'
$script_version      = '1.0'
$consultant_company  = 'Cutaway Security, LLC'
$company_lg          = 'ACME, Inc.'
$company_sh          = 'ACME'
$sitename            = 'plant1'
$start_time          = Get-Date -format yyyyMMddHHmmssff
$start_time_readable = Get-Date -Format "dddd MM/dd/yyyy HH:mm"
$computername        = $env:ComputerName
$runname             = $company_sh + '_' + $start_time
#$outdir              = "$env:APPDATA\$runname"
$outdir              = "C:\Users\student\Desktop\test\$runname"
$outfile             = $computername + '_NCAS_report_' + $start_time + '.txt'
$outfile_stub        = $computername + '_' + $start_time
$outpath             = "$outdir\$outfile"
$outpath_stub        = "$outdir\$outfile_stub"

#############################
# Script behavior parameters
#############################
$runstat             = $true # change to disable run status output
$cutsec_footer       = $true # change to false to disable CutSec footer




#############################
# Start script
#############################
if ($runstat) {Write-Host "NCAS run started at $start_time_readable on $computername"}

# Create output directory and file
if(!(Test-Path -Path $outdir )){
    New-Item -ItemType directory -Path $outdir | Out-Null
    if ($runstat) {Write-Host "Output folder created at: $outdir"}
}
else
{
  if ($runstat) {Write-Host "Folder already exists: $outdir"}
}

#############################
# Document Header
#############################
Write-Output "# $company_sh NCAS Data: $computername" | Out-File -FilePath $outpath -Append

Write-Output "`n## Computer Information`n" | Out-File -FilePath $outpath -Append
Write-Output "System Name: $computername" | Out-File -FilePath $outpath -Append
Write-Output "Company: $company_lg" | Out-File -FilePath $outpath -Append
Write-Output "Assessment Team: $consultant_company" | Out-File -FilePath $outpath -Append # comment this out or rename to team name
Write-Output "Script Version: $script_name $script_version" | Out-File -FilePath $outpath -Append
Write-Output "Start Time: $start_time_readable" | Out-File -FilePath $outpath -Append

#############################
# Gather inforamtion about computer version
#############################
Write-Output "`n## Computer Version`n" | Out-File -FilePath $outpath -Append
if ($runstat) {Write-Host "Gathering computer version information"}

$sysinfo = Get-ComputerInfo -Property WindowsProductName,OsVersion,WindowsCurrentVersion,WindowsVersion
$sysinfo | Format-Table -AutoSize | Out-File -FilePath $outpath -Append
$sysinfo | Format-Table -AutoSize | Out-File -FilePath $outpath_stub"_sysinfo.txt" -Append

$sysinfo_orig = systeminfo
$sysinfo_orig | Format-Table -AutoSize | Out-File -FilePath $outpath_stub"_orig_sysinfo.txt" -Append

#############################
# Gather inforamtion about security patches
#############################
Write-Output "`n## Security Patch Information`n" | Out-File -FilePath $outpath -Append
if ($runstat) {Write-Host "Gathering security patch information"}

$hotfixes = Get-Hotfix | Format-Table PSComputerName,Description,HotFixID,InstalledOn -AutoSize 
$hotfixes | Out-File -FilePath $outpath -Append
$hotfixes | Format-Table -AutoSize | Out-File -FilePath $outpath_stub"_hotfixes.txt" -Append

#############################
# Gather information about installed software
# Source: https://devblogs.microsoft.com/scripting/use-powershell-to-quickly-find-installed-software/
#############################
Write-Output "`n## Installed Software Information`n" | Out-File -FilePath $outpath -Append
if ($runstat) {Write-Host "Gathering installed software information"}

$array = @()

#Define the variable to hold the location of Currently Installed Programs
$UninstallKey=”SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall” 

#Create an instance of the Registry Object and open the HKLM base key
$reg=[microsoft.win32.registrykey]::OpenRemoteBaseKey(‘LocalMachine’,$computername) 

#Drill down into the Uninstall key using the OpenSubKey Method
$regkey=$reg.OpenSubKey($UninstallKey) 

#Retrieve an array of string that contain all the subkey names
$subkeys=$regkey.GetSubKeyNames() 

#Open each Subkey and use GetValue Method to return the required values for each
foreach($key in $subkeys){
    $thisKey=$UninstallKey+”\\”+$key 
    $thisSubKey=$reg.OpenSubKey($thisKey) 
    $obj = New-Object PSObject
    $obj | Add-Member -MemberType NoteProperty -Name “ComputerName” -Value $computername
    $obj | Add-Member -MemberType NoteProperty -Name “DisplayName” -Value $($thisSubKey.GetValue(“DisplayName”))
    $obj | Add-Member -MemberType NoteProperty -Name “DisplayVersion” -Value $($thisSubKey.GetValue(“DisplayVersion”))
    $obj | Add-Member -MemberType NoteProperty -Name “InstallLocation” -Value $($thisSubKey.GetValue(“InstallLocation”))
    $obj | Add-Member -MemberType NoteProperty -Name “Publisher” -Value $($thisSubKey.GetValue(“Publisher”))
    $array += $obj
} 

$array | Where-Object { $_.DisplayName } | select ComputerName, DisplayName, DisplayVersion, Publisher | Format-Table -AutoSize | Out-File -FilePath $outpath -Append
$array | Where-Object { $_.DisplayName } | select ComputerName, DisplayName, DisplayVersion, Publisher | Format-Table -AutoSize | Out-File -FilePath $outpath_stub"_software.txt" -Append

#############################
# Gather inforamtion about TCP and UDP Listening Services
# Source: https://jcutrer.com/powershell/network-daemons-parent-processes
#############################
Write-Output "`n## Network Connection Information`n" | Out-File -FilePath $outpath -Append
if ($runstat) {Write-Host "Gathering TCP and UDP Listening Services"}

# Make a lookup table by process ID
$Processes = @{}
Get-Process | ForEach-Object {
    $Processes[$_.Id] = $_
}

# Query Listening TCP Daemons
Write-Output "### TCP Daemons" | Out-File -FilePath $outpath -Append
Write-Output "# TCP Daemons" | Out-File -FilePath $outpath_stub"_network_services.txt" -Append
$tcpservers = Get-NetTCPConnection | 
    Where-Object { $_.State -eq "Listen" -and $_.LocalAddress -ne "127.0.0.1" } |
    Select-Object LocalAddress,
        LocalPort,
        @{Name="PID";         Expression={ $_.OwningProcess }},
        @{Name="ProcessName"; Expression={ $Processes[[int]$_.OwningProcess].ProcessName }}, 
        @{Name="Path"; Expression={ $Processes[[int]$_.OwningProcess].Path }} |
    Sort-Object -Property LocalPort, LocalAddress |
    Format-Table -AutoSize 
$tcpservers | Out-File -FilePath $outpath -Append
$tcpservers | Out-File -FilePath $outpath_stub"_network_services.txt" -Append

# Query Listening UDP Daemons
Write-Output "### UDP Daemons" | Out-File -FilePath $outpath -Append
Write-Output "# UDP Daemons" | Out-File -FilePath $outpath_stub"_network_services.txt" -Append
$udpservers = Get-NetUDPEndpoint | 
    Where-Object { $_.LocalAddress -ne "127.0.0.1" } |
    Select-Object LocalAddress,
        LocalPort,
        @{Name="PID";         Expression={ $_.OwningProcess }},
        @{Name="ProcessName"; Expression={ $Processes[[int]$_.OwningProcess].ProcessName }}, 
        @{Name="Path"; Expression={ $Processes[[int]$_.OwningProcess].Path }} |
    Sort-Object -Property LocalPort, LocalAddress |
    Format-Table -AutoSize | Out-File -FilePath $outpath -Append
$udpservers | Out-File -FilePath $outpath -Append
$udpservers | Out-File -FilePath $outpath_stub"_network_services.txt" -Append

# Footer
Write-Output "## Script Completed`n" | Out-File -FilePath $outpath -Append
$stop_time_readable = Get-Date -Format "dddd MM/dd/yyyy HH:mm"
Write-Output "NCAS run completed at $stop_time_readable" | Out-File -FilePath $outpath -Append

#############################
# Stop script
#############################
if ($runstat) {Write-Host "NCAS run finished at $stop_time_readable on $computername"}

#############################
# Cutaway Security Footer
#############################
if ($cutsec_footer -eq $true){
    Write-Output "`n>              *************                     " | Out-File -FilePath $outpath -Append
    Write-Output "> NCAS is brought to you by Cutaway Security, LLC" | Out-File -FilePath $outpath -Append
    Write-Output "> For assistance with your assessments, please contact info [@] cutawaysecurity.com" | Out-File -FilePath $outpath -Append
    Write-Output "> For recommendations or issues, please add an issues or create a pull request on GitHub, or contact dev [@] cutawaysecurity.com" | Out-File -FilePath $outpath -Append
    Write-Output ">              *************                     " | Out-File -FilePath $outpath -Append
}