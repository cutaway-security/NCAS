# NCAS

Following the requirements for NERC CIP-010-3.R1 a baseline must be created for each system. This project is designed to provide a set of scripts to run on a variety of systems to generate the required baseline outputs. These outputs will provide files for individual requirements and also, where possible, generate an HTML report for importing into reports.

## NERC CIP-010-3.R1 Requirements 

Develop a baseline configuration, individually or by group, which shall include the following items:

* 1.1.1. Operating system(s) (including version) or firmware where no independent operating system exists;
* 1.1.2. Any commercially available or open-source application software (including version) intentionally installed;
* 1.1.3. Any custom software installed;
* 1.1.4. Any logical network accessible ports; and
* 1.1.5. Any security patches applied.

# Scripts

## Name and Descriptions

* ncas_win10.ps1 - PS script to run on Windows 10 systems.

## Usage and Examples

### ncas_win10.ps1

```powershell
PS C:\Users\administrator> $env:APPDATA
C:\Users\administrator\AppData\Roaming
PS C:\Users\administrator> Set-ExecutionPolicy -Scope Process Bypass
PS C:\Users\administrator> .\ncas_win10.ps1
NCAS run started at Tuesday 03/15/2022 06:44 on SERV-HMI-01
Output folder created at: C:\Users\administrator\AppData\Roaming\ACME_2022031506441913                                           
Gathering computer version information                                                                                  
Gathering security patch information
Gathering installed software information
Gathering TCP and UDP Listening Services
NCAS run finished at Tuesday 03/15/2022 06:44 on SERV-HMI-01
```

# Contact
To request assistance or schedule an assessment, please contact Cutaway Security at 'info [@] cutawaysecurity.com'.
For information about this project please submit an issue or pull request via GitHub or contact us at 'dev [@] cutawaysecurity.com'.