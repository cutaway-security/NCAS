<#
	ncas_win7.ps1 - NERC CIP Audit Script for Windows 7. This script 
                     will collect data from the system and generate a
                     text and HTML report file, and provide individual
                     output files.
    Author: Don C. Weber (@cutaway)
    Date:   March 16, 2022
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
$script_name         = 'ncas_win7'
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
$report_name = "$company_sh NCAS Data: $computername`r`n"

$header_name   = "`n# Computer Information`r`n"
$report_header = "System Name: $computername`r`n"
$report_header += "Company: $company_lg`r`n"
$report_header += "Assessment Team: $consultant_company`r`n" # comment this out or rename to team name
$report_header += "Script Version: $script_name $script_version`r`n"
$report_header += "Start Time: $start_time_readable`r`n"

# Header info for Text Report
$report_name | Out-File -FilePath $outpath -Append
$header_name+$report_header | Out-File -FilePath $outpath -Append

# Header info for HTML Report
$report_name_HTML = "<html><header></header><body><h1>$report_name</h1>"
$report_header_HTML = "<h2>" + ($header_name -replace "`r`n","") + "</h2><p>" + ($report_header -replace "`n","<br>") + "</p>"


#############################
# Gather inforamtion about computer version
#############################
$sysinfo_header = "`n# Computer Version`n" 
if ($runstat) {Write-Host "Gathering computer version information"}

# Grab System info 
$sysinfo = systeminfo
$sys_os = $sysinfo | Select-String 'OS'

# System info for Text Report
$sysinfo_header | Out-File -FilePath $outpath -Append
$sys_os | Out-File -FilePath $outpath -Append
$sysinfo | Format-Table -AutoSize | Out-File -FilePath $outpath_stub"_orig_sysinfo.txt" -Append

# System info for HTML Report
$sys_br = foreach ($l in $sys_os){($l -replace "`$","</br>")}
$sysinfo_HTML = "<h2>" + ($sysinfo_header  -replace "`n","") + "</h2><p>" + $sys_br + "</p>"

#############################
# Gather inforamtion about security patches
#############################
$hf_header = "`n## Security Patch Information`n"
if ($runstat) {Write-Host "Gathering security patch information"}

$hotfixes = Get-Hotfix 

# Hotfix info for Text Report
$hf_header | Out-File -FilePath $outpath -Append
$hotfixes | Format-Table Description,HotFixID,InstalledOn -AutoSize | Out-String -Width 4096 | Out-File -FilePath $outpath -Append
$hotfixes | Format-Table Description,HotFixID,InstalledOn -AutoSize | Out-String -Width 4096 | Out-File -FilePath $outpath_stub"_hotfixes.txt" -Append

# Hotfix info for HTML Report
$hf_br =  foreach ($l in ($hotfixes | Format-Table Description,HotFixID,InstalledOn -AutoSize | Out-String -Width 4096)){($l -replace "`r","</br>")}
$hotfix_HTML = "<h2>" + ($hf_header  -replace "`n","") + "</h2><p>" + $hf_br + "</p>"

#############################
# Gather information about installed software
# Source: https://devblogs.microsoft.com/scripting/use-powershell-to-quickly-find-installed-software/
#############################
$sw_header = "`n# Installed Software Information`n"
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
 | select DisplayName, DisplayVersion, Publisher, InstallLocation `
 | Format-Table -AutoSize | Out-String -Width 4096
 

# Software info for Text Report
$sw_header | Out-File -FilePath $outpath -Append
$software_versions | Out-File -FilePath $outpath -Append
$software_versions | Out-File -FilePath $outpath_stub"_software.txt" -Append

# Software info for HTML Report
## Have to hack this string to get HTML breaks at the end if each line, plus handle the seperator dashes
$soft_hack = $array | Where-Object {$_.DisplayName } | Format-Table -Property DisplayName, DisplayVersion, Publisher, InstallLocation, @{Label="</br>";Expression={"</br>"}} -AutoSize | Out-String -Width 4096
$soft_br = $soft_hack -replace "-----`r","</br>"
$software_HTML = "<h2>" + ($sw_header  -replace "`n","") + "</h2><p>" + $soft_br + "</p>"

#############################
# Gather inforamtion about TCP and UDP Listening Services
# Source: https://jcutrer.com/powershell/network-daemons-parent-processes
#############################
$net_header = "`n# Network Connection Information`n"
if ($runstat) {Write-Host "Gathering TCP and UDP Listening Services"}

# Query Listening Network Daemons
$nets = netstat -ano | Select-String -Pattern LISTENING,UDP,PID
$netconns = foreach($n in $nets){
    # Process Header line and continue
    if ($n -match 'PID'){$n -replace "PID","Process"; continue}
    # make split easier PLUS make it a string instead of a match object:
    $p = $n -replace ' +',' '
    # make it an array:
    $nar = $p.Split(' ')
    # pick last item:
    $pname = $(Get-Process -id $nar[-1]).ProcessName
    $ppath = $(Get-Process -id $nar[-1]).Path
    # print the modified line with processname instead of PID:
    if ($ppath){$n -replace "$($nar[-1])`$","$($ppath)"}
    else {$n -replace "$($nar[-1])`$","$($pname)"}
    
}

# Network info for Text Report
$net_header | Out-File -FilePath $outpath -Append
$netconns | Out-File -FilePath $outpath -Append
$netconns | Out-File -FilePath $outpath_stub"_network_services.txt" -Append

# Network info for HTML Report
$net_br = foreach ($l in $netconns){($l + "</br>")}
$network_HTML = "<h2>" + ($net_header  -replace "`n","") + "</h2><p>" + $net_br + "</p>"

#############################
# Footer
#############################
Write-Output "`r`n# Script Completed`r`n" | Out-File -FilePath $outpath -Append
$stop_time_readable = Get-Date -Format "dddd MM/dd/yyyy HH:mm"
$completed = "NCAS run completed at " + $stop_time_readable + "`r`n"
Write-Output $completed | Out-File -FilePath $outpath -Append

$completed_HTML = "<h2>Script Completed</h2><p>" + $completed + "</p>" 

#############################
# Cutaway Security Footer
#############################

$cutsec_footer =  "`r`n****************************************************`r`n"
$cutsec_footer += "NCAS is brought to you by Cutaway Security, LLC`r`n"
$cutsec_footer += "For assistance with your assessments, please contact info [@] cutawaysecurity.com`r`n"
$cutsec_footer += "For recommendations or issues, please add an issues or create a pull request on GitHub, or contact dev [@] cutawaysecurity.com`r`n"
$cutsec_footer += "****************************************************`r`n"

$cutsec_footer_HTML = "<p>Creation Date: " + $stop_time_readable + "</p></body></html>"
if ($cutsec_footer){
    $cutsec_footer | Out-File -FilePath $outpath -Append
    $cutsec_footer_HTML = "<p>" + ($cutsec_footer -replace "`r`n","</br>") + "</p><p>Creation Date: " + $stop_time_readable + "</body></html>"
}

#############################
# Stop script
#############################
if ($runstat) {Write-Host "NCAS run finished at $stop_time_readable on $computername"}
$report_HTML = $report_name_HTML + " " + $report_header_HTML + " " + $sysinfo_HTML + " " + `
    $hotfix_HTML + " " + $software_HTML + " " + $network_HTML + " " + $completed_HTML + " " + $cutsec_footer_HTML
$report_HTML | Out-File -FilePath $outpath_html 