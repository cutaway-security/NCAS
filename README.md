# NCAS

Following the requirements for NERC CIP-010-3.R1 a baseline must be created for each system. The NERC CIP Assessment Scripts (NCAS) project is designed to provide a set of scripts to run on a variety of systems to generate the required baseline outputs. These outputs will provide files for individual requirements.

## NERC CIP-010-3.R1 Requirements 

Develop a baseline configuration, individually or by group, which shall include the following items:

* 1.1.1. Operating system(s) (including version) or firmware where no independent operating system exists;
* 1.1.2. Any commercially available or open-source application software (including version) intentionally installed;
* 1.1.3. Any custom software installed;
* 1.1.4. Any logical network accessible ports; and
* 1.1.5. Any security patches applied.

# Disclaimer

The NCAS scripts are distributed in the hope that they will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. These scripts are designed for information gathering only and will not make any changes or write any files to the system. However, running any program or script on a workstation or server can produce unintentional results. Use these scripts at your own risk.

Organizations using these scripts for NERC CIP compliance must review the output of the scripts to ensure they meet the intended results. While CutSec will make efforts to maintain and update this project, it will naturally lag NERC CIP updates and cannot predict every organization's requirements. Review the script outputs with your organization's requirements.

# Scripts

## Requirements

* PowerShell version 3 or greater. This is because PSv3 provides the Get-CIMInstance cmdlet. The scripts will run in PSv2 and PSv3 without the necessary CIM namespaces. However, the checks may produce errors and no data for some checks. 

## Name and Descriptions

* ncas_collector.ps1 - Collects the following information:
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
* ncas_dfir.ps1 - Collects all collector script data plus the following volatile data:
  * Network TCP Connections
  * Network UDP Connections
  * Process Memory Usage
  * Scheduled Tasks
  * USB Device History
  * Authentication Events

## Windows Systems Tested 

* Workstation 7/10/11
* Server 2012/2016/2019

# Contact
To request assistance or schedule an assessment, please contact Cutaway Security at 'info [@] cutawaysecurity.com'.
For information about this project please submit an issue or pull request via GitHub or contact us at 'dev [@] cutawaysecurity.com'.