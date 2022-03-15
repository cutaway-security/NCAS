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
# Script behavior parameters
#############################
$runstat             = $true # change to disable run status output
$cutsec_footer       = $true # change to false to disable CutSec footer
$consultant_company  = 'Cutaway Security, LLC'
$company_lg          = 'ACME, Inc.'
$company_sh          = 'ACME'
$sitename            = 'plant1'

#############################
# Set up document header information
#############################
$script_name         = 'ncas_win10'
$script_version      = '1.0'
$start_time          = Get-Date -format yyyyMMddHHmmssff
$start_time_readable = Get-Date -Format "dddd MM/dd/yyyy HH:mm"
$computername        = $env:ComputerName
$runname             = $company_sh + '_' + $start_time
$outdir              = "$env:APPDATA\$runname"
$outfile             = $computername + '_NCAS_report_' + $start_time + '.txt'
$outhtml             = $computername + '_NCAS_report_' + $start_time + '.html'
$outfile_stub        = $computername + '_' + $start_time
$outpath             = "$outdir\$outfile"
$outpath_stub        = "$outdir\$outfile_stub"
$outpath_html        = "$outdir\$outhtml"

$Header = @"
<style>
TABLE {border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}
TH {border-width: 1px; padding: 3px; border-style: solid; border-color: black; background-color: #6495ED;}
TD {border-width: 1px; padding: 3px; border-style: solid; border-color: black;}
</style>
"@

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
$report_name = "$company_sh NCAS Data: $computername`n"

$header_name   = "`nComputer Information`n"
$report_header = "System Name: $computername`n"
$report_header += "Company: $company_lg`n"
$report_header += "Assessment Team: $consultant_company`n" # comment this out or rename to team name
$report_header += "Script Version: $script_name $script_version`n"
$report_header += "Start Time: $start_time_readable`n"

$report_name | Out-File -FilePath $outpath -Append
$report_name_HTML = "<h1>$report_name</h1>"
$header_name+$report_header | Out-File -FilePath $outpath -Append
#$report_header_HTML = $report_header | ConvertTo-Html -Fragment -PreContent "<h2>Computer Information</h2>"
$report_header_HTML = "<h2>$header_name</h2><p>" + $report_header.Replace("`n","<br>") + "</p>"

#############################
# Gather inforamtion about computer version
#############################
Write-Output "`n## Computer Version`n" | Out-File -FilePath $outpath -Append
if ($runstat) {Write-Host "Gathering computer version information"}

$sysinfo = Get-ComputerInfo -Property WindowsProductName,OsVersion,WindowsCurrentVersion,WindowsVersion
$sysinfo | Format-Table -AutoSize | Out-File -FilePath $outpath -Append
$sysinfo | Format-Table -AutoSize | Out-File -FilePath $outpath_stub"_sysinfo.txt" -Append
$sysinfo_HTML = $sysinfo | ConvertTo-Html -Fragment -PreContent "<h2>Computer Version Information</h2>"

# Output the old systeminfo file which can be feed into WES-NG for patch vulnerability information
$sysinfo_orig = systeminfo
$sysinfo_orig | Format-Table -AutoSize | Out-File -FilePath $outpath_stub"_orig_sysinfo.txt" -Append

#############################
# Gather inforamtion about security patches
#############################
Write-Output "`n## Security Patch Information`n" | Out-File -FilePath $outpath -Append
if ($runstat) {Write-Host "Gathering security patch information"}

$hotfixes = Get-Hotfix 
$hotfixes | Format-Table PSComputerName,Description,HotFixID,InstalledOn -AutoSize | Out-File -FilePath $outpath -Append
$hotfixes | Format-Table PSComputerName,Description,HotFixID,InstalledOn -AutoSize | Out-File -FilePath $outpath_stub"_hotfixes.txt" -Append
$hotfixes_HTML = $hotfixes | ConvertTo-Html -Property PSComputerName,Description,HotFixID,InstalledOn -Fragment -PreContent "<h2>Security Patch Information</h2>"

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

$software_versions = $array | Where-Object { $_.DisplayName } `
 | select ComputerName, DisplayName, DisplayVersion, Publisher `
 | Format-Table -AutoSize | Out-String -Width 4096

$software_versions | Out-File -FilePath $outpath -Append
$software_versions | Out-File -FilePath $outpath_stub"_software.txt" -Append
$software_HTML = $array | Where-Object { $_.DisplayName } | ConvertTo-Html -Fragment -PreContent "<h2>Installed Software Information</h2>"

#############################
# Gather inforamtion about TCP and UDP Listening Services
# Source: https://jcutrer.com/powershell/network-daemons-parent-processes
#############################
Write-Output "`n## Network Connection Information`n" | Out-File -FilePath $outpath -Append
if ($runstat) {Write-Host "Gathering TCP and UDP Listening Services"}
$net_servers_HTML = "<h2>Network Connection Information</h2>"

# Make a lookup table by process ID
$Processes = @{}
Get-Process | ForEach-Object {
    $Processes[$_.Id] = $_
}

# Query Listening TCP Daemons
Write-Output "### TCP Network Servers" | Out-File -FilePath $outpath -Append
Write-Output "# TCP Network Servers" | Out-File -FilePath $outpath_stub"_network_services.txt" -Append
$tcpservers = Get-NetTCPConnection | 
    Where-Object { $_.State -eq "Listen" -and $_.LocalAddress -ne "127.0.0.1" } |
    Select-Object LocalAddress,
        LocalPort,
        @{Name="PID";         Expression={ $_.OwningProcess }},
        @{Name="ProcessName"; Expression={ $Processes[[int]$_.OwningProcess].ProcessName }}, 
        @{Name="Path"; Expression={ $Processes[[int]$_.OwningProcess].Path }} |
    Sort-Object -Property LocalPort, LocalAddress 
$tcpservers | Format-Table -AutoSize | Out-String -Width 4096 | Out-File -FilePath $outpath -Append
$tcpservers | Format-Table -AutoSize | Out-String -Width 4096 | Out-File -FilePath $outpath_stub"_network_services.txt" -Append
$tcp_servers_HTML = $tcpservers | ConvertTo-Html -Fragment -PreContent "<h3>TCP Network Servers</h3>"

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
    Sort-Object -Property LocalPort, LocalAddress
$udpservers | Format-Table -AutoSize | Out-String -Width 4096 | Out-File -FilePath $outpath -Append
$udpservers | Format-Table -AutoSize | Out-String -Width 4096 | Out-File -FilePath $outpath_stub"_network_services.txt" -Append
$udp_servers_HTML = $udpservers | ConvertTo-Html -Fragment -PreContent "<h3>UDP Network Servers</h3>"

# Footer
Write-Output "## Script Completed`n" | Out-File -FilePath $outpath -Append
$stop_time_readable = Get-Date -Format "dddd MM/dd/yyyy HH:mm"
$completed = "NCAS run completed at $stop_time_readable"
Write-Output $completed | Out-File -FilePath $outpath -Append

$completed_HTML = "<h2>Script Completed</h2><p>" + $completed + "</p>" 

#############################
# Cutaway Security Footer
#############################

$cutsec_footer =  "****************************************************`n"
$cutsec_footer += "NCAS is brought to you by Cutaway Security, LLC`n"
$cutsec_footer += "For assistance with your assessments, please contact info [@] cutawaysecurity.com`n"
$cutsec_footer += "For recommendations or issues, please add an issues or create a pull request on GitHub, or contact dev [@] cutawaysecurity.com`n"
$cutsec_footer += "****************************************************`n"

$cutsec_footer_HTML = '<p></p>'
if ($cutsec_footer){
    $cutsec_footer | Out-File -FilePath $outpath -Append
    $cutsec_footer_HTML = "<p>" + $cutsec_footer.Replace("`n","</br>") + "</p>"
}

#############################
# Stop script
#############################
if ($runstat) {Write-Host "NCAS run finished at $stop_time_readable on $computername"}
$report_HTML = ConvertTo-HTML -Head $Header -Body `
 "$report_name_HTML $report_header_HTML $sysinfo_HTML $hotfixes_HTML $software_HTML $net_servers_HTML $tcp_servers_HTML $udp_servers_HTML $completed_HTML $cutsec_footer_HTML" `
 -Title "$report_name" -PostContent "<p>Creation Date: $stop_time_readable<p>"
$report_HTML | Out-File -FilePath $outpath_html 