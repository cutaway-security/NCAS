@echo off

rem ncas_collector.bat - NERC CIP Assessment Script for Windows system
rem with no PowerShell greater than 3. This script will collect 
rem data from the system using system programs and output to the 
rem text files in a directory named with the hostname, date, and time.
rem 
rem Author: Don C. Weber (@cutaway)
rem Date:   February 26, 2024
rem 
rem License: 
rem Copyright (c) 2024, Cutaway Security, Inc. <dev [@] cutawaysecurity.com>
rem 	
rem ncas_collector.bat is free software: you can redistribute it and/or modify
rem it under the terms of the GNU General Public License as published by
rem the Free Software Foundation, either version 3 of the License, or
rem (at your option) any later version.
rem 
rem ncas_collector.bat is distributed in the hope that it will be useful,
rem but WITHOUT ANY WARRANTY; without even the implied warranty of
rem MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
rem GNU General Public License for more details.
rem You should have received a copy of the GNU General Public License
rem along with this program.  If not, see <http://www.gnu.org/licenses/>.
rem Point Of Contact:    Don C. Weber <dev [@] cutawaysecurity.com>

rem ##########################
rem Script behavior parameters
rem ##########################
set DEBUG=
set PRINTORG=y
set ORG_NAME=Cutaway Security, LLC
set ORG_CONTACT=dev@cutawaysecurity.com
set VERSION=0.1
set HOSTNAME=%COMPUTERNAME%

CALL :getDate STARTSTAMP
echo ##########################
echo NCAS Script Started at %STARTSTAMP%
echo ##########################
echo.

rem ##########################
echo Checking for Administrator Rights
rem ##########################
CALL :isAdmin
if %errorlevel% == 0 (
    echo Running with Administrative privileges.
) else (
    echo Not running with Administrative privileges. Exiting.
    goto :eof
)

rem ##########################
rem Create output directory
rem ##########################
IF defined DEBUG echo outdir: %HOSTNAME%_%STARTSTAMP%
set OUTDIR=%HOSTNAME%_%STARTSTAMP%

IF exist %OUTDIR% (
    mkdir %OUTDIR%_2
) ELSE (
    mkdir %OUTDIR%
)
echo Script results will be placed in: %OUTDIR%
cd %OUTDIR%

rem ##########################
echo Get System Information
rem ##########################
systeminfo > systeminfo.txt

rem ##########################
echo Get Installed Sofware - wmic
rem ##########################
wmic product get Name,Version,Installdate /format:csv > software-wmic.csv

rem ##########################
echo Get Installed Sofware - dir
rem ##########################
IF EXIST "C:\" (
    echo ##### >> software-dir.txt
    echo "Listing C:\ directory" >> software-dir.txt
    echo ##### >> software-dir.txt
    dir "C:\" /A:D >> software-dir.txt
    echo. >> software-dir.txt
)
IF EXIST "C:\Program Files\" (
    echo ##### >> software-dir.txt
    echo "Listing C:\Program Files\ directory" >> software-dir.txt
    echo ##### >> software-dir.txt
    dir "C:\Program Files\" /A:D >> software-dir.txt
    echo. >> software-dir.txt
)
IF EXIST "C:\Program Files (x86)\" (
    echo ##### >> software-dir.txt
    echo "Listing C:\Program Files (x86)\ directory" >> software-dir.txt
    echo ##### >> software-dir.txt
    dir "C:\Program Files (x86)\" /A:D >> software-dir.txt
    echo. >> software-dir.txt
)

rem ##########################
echo Get Installed Patches
rem ##########################
wmic qfe get HotFixID,InstalledBy,InstalledOn /format:csv > patches-wmic.csv

rem ##########################
echo Get Auto Started Services
rem ##########################
wmic service where StartMode="Auto" get Name,StartName,StartMode,PathName /format:csv > services_auto-wmic.csv

rem ##########################
echo Get All Services
rem ##########################
wmic service get Name,StartName,StartMode,PathName /format:csv > services_all-wmic.csv

rem ##########################
echo Get Running Processes - wmic
rem ##########################
wmic process get Name,ProcessId,ExecutablePath,CommandLine /format:csv > running_processes-wmic.csv

rem ##########################
echo Get Running Processes - tasklist
rem ##########################
tasklist > running_processes-tasklist.txt

rem ##########################
echo Get Running Process Services - tasklist
rem ##########################
tasklist /SVC > running_process_services-tasklist.txt

rem ##########################
echo Get Scheduled Tasks - schtasks
rem ##########################
schtasks /query /fo list /v > scheduled_tasks-schtasks.txt

rem ##########################
echo Get Listening Services - netstat
rem ##########################
netstat -ano | find /i "listening" > listening_services-netstat.txt

rem ##########################
echo Get Network Connections - netstat
rem ##########################
netstat -anob > network_connections-netstat.txt

rem ##########################
echo Get Local User Accounts - wmic
rem ##########################
wmic useraccount get SID,Name,PasswordRequired,Lockout /format:csv > local_accounts-wmic.csv

rem ##########################
echo Get Local User Accounts - net 
rem ##########################
net user > local_accounts-net.txt

rem ##########################
echo Get Local Groups - wmic
rem ##########################
wmic group get Name,SID /format:csv > localgroups-wmic.csv

rem ##########################
echo Get Local Groups - net 
rem ##########################
net localgroup > localgroups-net.txt

rem ##########################
echo Get Local Administrators - wmic
rem ##########################
wmic path win32_groupuser where (groupcomponent="win32_group.name=\"administrators\",domain=\"%Computername%\"") > local_admins-wmic.txt

rem ##########################
echo Get Local Administrators - net
rem ##########################
net localgroup Administrators > localgroups_admins-net.txt

rem ##########################
echo Get Network Interfaces - wmic
rem ##########################
wmic nicconfig where ipenabled=true get Description,Index,MACAddress,IPAddress,IPSubnet,DefaultIPGateway,DNSServerSearchOrder /format:csv > network_interfaces-wmic.csv

rem ##########################
echo Get Network Interfaces - ipconfig
rem ##########################
ipconfig /all > network_interfaces-ipconfig.txt

rem ##########################
echo Get Network Routes - route
rem ##########################
route PRINT > network_routes-route.txt

rem ##########################
echo Get Local Network Addresses - arp
rem ##########################
arp -a > arp.txt

rem ##########################
echo Get Network Shares - wmic
rem ##########################
wmic share get Name,Path,Description /format:csv > shares-wmic.csv

rem ##########################
echo Get Network Shares - net
rem ##########################
net share > shares-net.txt

rem ##########################
rem Completed
rem ##########################
cd ..
CALL :getDate ENDSTAMP
echo.
echo ##########################
echo NCAS Script Completed at %ENDSTAMP%
IF defined PRINTORG echo Brought to you by %ORG_NAME%
IF defined PRINTORG echo Contact %ORG_CONTACT% with any questions or requests.
echo ##########################
goto :eof

rem ##########################
rem Functions
rem ##########################

:getDate
rem ##########################
rem Get date and time for outputs
rem ##########################
for /f "tokens=2 delims==" %%a in ('wmic OS Get localdatetime /value') do set "dt=%%a"
set "YY=%dt:~2,2%" & set "YYYY=%dt:~0,4%" & set "MM=%dt:~4,2%" & set "DD=%dt:~6,2%"
set "HH=%dt:~8,2%" & set "Min=%dt:~10,2%" & set "Sec=%dt:~12,2%"

set DATESTAMP=%YYYY%%MM%%DD%
set TIMESTAMP=%HH%%Min%%Sec%
set %~1=%DATESTAMP%_%TIMESTAMP%
goto :eof

:isAdmin
rem ##########################
rem Check for Administrator Rights
rem ##########################
fsutil dirty query %systemdrive% >nul
goto :eof