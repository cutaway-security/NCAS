# NCAS

Following the requirements for NERC CIP-010-3.R1 a baseline must be created for each system. The NERC CIP Assessment Scripts (NCAS) project is designed to provide a set of scripts to run on a variety of systems to generate the required baseline outputs. These outputs will provide files for individual requirements.

## NERC CIP-010-3.R1 Requirements 

Develop a baseline configuration, individually or by group, which shall include the following items:

* 1.1.1. Operating system(s) (including version) or firmware where no independent operating system exists;
* 1.1.2. Any commercially available or open-source application software (including version) intentionally installed;
* 1.1.3. Any custom software installed;
* 1.1.4. Any logical network accessible ports; and
* 1.1.5. Any security patches applied.

## Disclaimer ***Please read before use in NERC CIP efforts.***

The NCAS scripts are distributed in the hope that they will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. These scripts are designed for information gathering only and will not make any changes or write any files to the system. However, running any program or script on a workstation or server can produce unintentional results. Use these scripts at your own risk.

Organizations using these scripts for NERC CIP compliance must review the output of the scripts to ensure they meet the intended results. While CutSec will make efforts to maintain and update this project, it will naturally lag NERC CIP updates and cannot predict every organization's requirements. Review the script outputs with your organization's requirements.

# Scripts

## Requirements
* CMD Version
  * Administrator rights
* PSv2 Version
  * PowerShell version 2 (should work on greater)
  * Administrator rights
* PSv3 Version
  * PowerShell version 3 or greater. This is because PSv3 provides the Get-CIMInstance cmdlet. The scripts will run in PSv2 and PSv3 without the necessary CIM namespaces. However, the checks may produce errors and no data for some checks. 

## Name and Descriptions
* CMD
  * ncas_collector.bat - Collects the following information in individual files in a directory named for the host and time of run:
    * Computer Information
    * Installed Applications
    * Installed Patches
    * Installed Services
    * Local User Accounts
    * Local Group Accounts
    * Local Group Memberships
    * Network Interfaces
    * File Shares 
* PowerShellv2
  * ncas_collector_PSv2.ps1 - Collects the following information in individual files in a directory named for the host and time of run:
    * Computer Information
    * Installed Applications
    * Installed Patches
    * Installed Services
    * Local User Accounts
    * Local Group Accounts
    * Local Group Memberships
    * Event Log Settings
    * Anti-Virus Status 
    * Network Interfaces
    * Common Vulnerability Checks
    * File Shares 
* PowerShellv3
  * ncas_collector_PSv3.ps1 - Collects the following information output to the screen:
    * Computer Information
    * Installed Applications
    * Installed Patches
    * Installed Services
    * Local User Accounts
    * Local Group Accounts
    * Local Group Memberships
    * Event Log Settings
    * Anti-Virus Status 
    * Network Interfaces
    * Common Vulnerability Checks
    * File Shares 
  * ncas_dfir_PSv3.ps1 - Collects all PSv3 collector script data plus the following volatile data:
    * Network TCP Connections
    * Network UDP Connections
    * Process Memory Usage
    * Scheduled Tasks
    * USB Device History
    * Authentication Events
* VulnChecker
  * CPEtoCVE.ps1 - PS script that takes a file with CPE product values and checks for CVEs. See TODO list.

## Usage
### CMD Version
* Copy the `ncas_collector.bat` script to the Desktop, Downloads, or Documents directory of the target system.
* Start CMD as an Administrator. Check the title bar for the word `Administrator`.
* Change into the directory that contains the script.
* Type `.\ncas_collector.bat` and monitor output to screen. Note any errors for notes.
* Check for the output directory and review the contents of each file to confirm information.
* Copy folder to storage location or device. Confirm copied files.
* Close the CMD window.
* Remove output directory and script from target system

### PSv2 Version
* Copy the `ncas_collector_PSv2.ps1` script to the Desktop, Downloads, or Documents directory of the target system.
* Start PowerShell as an Administrator. Check the title bar for the word `Administrator`.
* Confirm PS version by running `$PSVersionTable.PSVersion.Major`. The result should be `2`.
* Enable running PS script in the current PS process by running `Set-ExecutionPolicy Bypass -Scope Process`.
* Change into the directory that contains the script.
* Type `.\ncas_collector_PSv2.ps1` and monitor output to screen. Note any errors for notes.
* Check for the output directory and review the contents of each file to confirm information.
* Copy folder to storage location or device. Confirm copied files.
* Close the PS window.
* Remove output directory and script from target system
### PSv3 Version
* Copy the `ncas_collector_PSv3.ps1` or `ncas_dfir_PSv3.ps1` script to the Desktop, Downloads, or Documents directory of the target system.
* Start PowerShell as an Administrator. Check the title bar for the word `Administrator`.
* Confirm PS version by running `$PSVersionTable.PSVersion.Major`. The result should be `3` or greater.
* Enable running PS script in the current PS process by running `Set-ExecutionPolicy Bypass -Scope Process`.
* Change into the directory that contains the script.
* Type `.\ncas_collector.ps1 > ${env:computername}_ncas_collector_$(Get-Date -Format "yyyyddMM_HHmmss").txt` (or the DFIR script) and monitor output to screen. Note any errors for notes.
* Check for the local directory and review the contents of the output file and the `systeminfo` file to confirm information.
* Copy files to storage location or device. Confirm copied files.
* Close the PS window.
* Remove output directory and script from target system

## Windows Systems Tested 

* CMD Version
  * Workstation XP,7,10,11
* PSv2 Version
  * Workstation 7,10
* PSv3 Version
  * Workstation 7/10/11
  * Server 2012/2016/2019

## TODO

* CMD Version
  * Clean up output
  * Make HTML output
* PSv2 Version
  * Make HTML output
* PSv3 Version
  * Update script to write to a directory and separate files.
  * Make HTML output
* VulnChecker
  * Add time boundaries to searches
  * Identify vendor strings for common software and industrial vendors

# Collaborators
CutSec would like to thank the following people and organizations for contributing, testing, and troubleshooting this project.

* Tom Liston - Bad Wolf Security, LLC
* Aaron Crow - [Corvo Security, LLC](https://corvosec.com/)

# Contact
To request assistance or schedule an assessment, please contact Cutaway Security at 'info [@] cutawaysecurity.com'.
For information about this project please submit an issue or pull request via GitHub or contact us at 'dev [@] cutawaysecurity.com'.