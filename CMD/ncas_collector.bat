@echo off

rem ncas_collector.bat - NERC CIP Assessment Script for Windows system
rem with no PowerShell greater than 3. This script will collect 
rem data from the system using system programs and output to the 
rem text files in a directory named with the hostname, date, and time.
rem 
rem Author: Don C. Weber (@cutaway)
rem Date:   March 1, 2024
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
rem Collection parameters
rem To disable a check remove the 'y' at the end of the following lines
rem Disable check for patches, update line to read 'set PATCHES='
rem ##########################
set SYSINFO=y
set INSTALLEDSOFTWARE=y
set PATCHES=y
set PROCESSES=y
set SERVICES=y
set TASKS=y
set LISTENINGSERVICES=y
set LOCALACCOUNTS=y
set LOCALGROUPS=y
set LOCALADMIN=y
set INTERFACES=y
set ROUTES=y
set ARPCACHE=y
set SHARES=y

rem ##########################
rem Script behavior parameters
rem ##########################
set DEBUG=
set PRINTDEV=y
set VERSION=1.1
set VER_DATE=20240301
set HOSTNAME=%COMPUTERNAME%

CALL :getDate STARTSTAMP
echo ##########################
echo NCAS Script v%VERSION% Started at %STARTSTAMP%
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
echo.

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
echo.

rem ##########################
rem Get Data
rem ##########################
IF defined SYSINFO CALL :getSysInfo
IF defined INSTALLEDSOFTWARE CALL :getInstalled
IF defined PATCHES CALL :getPatches
IF defined PROCESSES CALL :getProcesses
IF defined SERVICES CALL :getServices
IF defined TASKS CALL :getScheduledTasks
IF defined LISTENINGSERVICES CALL :getListening
IF defined LOCALACCOUNTS CALL :getLocalAccounts
IF defined LOCALGROUPS CALL :getLocalGroups
IF defined LOCALADMIN CALL :getAdminUsers
IF defined INTERFACES CALL :getInterfaces
IF defined ROUTES CALL :getNetRoutes
IF defined ARPCACHE CALL :getARPCache
IF defined SHARES CALL :getNetShares

rem ##########################
rem Completed
rem ##########################
cd ..
CALL :getDate ENDSTAMP
echo.
echo ##########################
echo NCAS Script Completed at %ENDSTAMP%
IF defined PRINTDEV echo Brought to you by Cutaway Security, LLC
IF defined PRINTDEV echo For assessment and auditing help, contact info [@] cutawaysecurity.com
IF defined PRINTDEV echo For script help, contact dev [@] cutawaysecurity.com
echo ##########################
goto :eof

rem ##########################
rem Admin Functions
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

:printCollectionHeader
rem ##########################
rem Print Collection Header
rem ##########################
echo %~1

:isAdmin
rem ##########################
rem Check for Administrator Rights
rem ##########################
fsutil dirty query %systemdrive% >nul
goto :eof

rem ##########################
rem Collection Functions
rem ##########################

:getInstalled
CALL :printCollectionHeader "Get Installed Sofware"
wmic product get Name,Version,Installdate /format:csv > software.csv
rem NOTE: Add system and user registry HIVE checks here

rem Get Installed Sofware using dir method (does not get version)
rem NOTE: Use GOTO to skip this code as commented out.
GOTO EndComment0
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
:EndComment0
goto :eof

:getSysInfo
CALL :printCollectionHeader "Get System Information"
systeminfo > systeminfo.txt
goto :eof

:getPatches
CALL :printCollectionHeader "Get Installed Patches"
wmic qfe get HotFixID,InstalledBy,InstalledOn /format:csv > patches.csv
goto :eof

:getProcesses
CALL :printCollectionHeader "Get Running Processes"
wmic process get Name,ProcessId,ExecutablePath,CommandLine /format:csv > running_processes.csv
goto :eof

:getServices
CALL :printCollectionHeader "Get Services"
tasklist /SVC > running_process_services.txt
wmic service get Name,StartName,StartMode,PathName /format:csv > services_all.csv
goto :eof

:getScheduledTasks
CALL :printCollectionHeader "Get Scheduled Tasks"
schtasks /query /fo csv /v > scheduled_tasks.csv
goto :eof

:getListening
CALL :printCollectionHeader "Get Listening Services"
netstat -ano | find /i "listening" > listening_services.txt
goto :eof

:getLocalAccounts
CALL :printCollectionHeader "Get Local Accounts"
wmic useraccount get SID,Name,PasswordRequired,Lockout /format:csv > local_accounts.csv
rem Uncomment these lines to use net command
rem CALL :printCollectionHeader "Get Local Accounts - net"
rem net user > local_accounts-net.txt
goto :eof

:getLocalGroups
CALL :printCollectionHeader "Get Local Groups"
wmic group get Name,SID /format:csv > localgroups.csv
rem Uncomment these lines to use net command
rem CALL :printCollectionHeader "Get Local Groups - net"
rem net localgroup > localgroups-net.txt
goto :eof

:getAdminUsers
CALL :printCollectionHeader "Get Local Administrators"
wmic path win32_groupuser where (groupcomponent="win32_group.name=\"administrators\",domain=\"%Computername%\"") > local_admins.txt
rem Uncomment these lines to use net command
rem CALL :printCollectionHeader "Get Local Administrators - net"
rem net localgroup Administrators > localgroups_admins-net.txt
goto :eof

:getInterfaces
CALL :printCollectionHeader "Get Network Interfaces"
wmic NICCONFIG where IPEnabled='true' get DefaultIPGateway,Description,DHCPServer,DNSServerSearchOrder,IPAddress,IPSubnet,MACAddress /format:csv > network_interfaces.csv
rem Uncomment these lines to use net command
rem CALL :printCollectionHeader "Get Network Interfaces - ipconfig"
rem ipconfig /all > network_interfaces-ipconfig.txt
goto :eof

:getNetRoutes
CALL :printCollectionHeader "Get Network Routes"
route PRINT > network_routes.txt
goto :eof

:getARPCache
CALL :printCollectionHeader "Get ARP Cache"
arp -a > arp.txt
goto :eof

:getNetShares
CALL :printCollectionHeader "Get Network Shares"
wmic share get Name,Path,Description /format:csv > shares.csv
rem Uncomment these lines to use net command
rem CALL :printCollectionHeader "Get Network Shares - net"
rem net share > shares-net.txt
goto :eof