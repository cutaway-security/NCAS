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

* ncas_collector.ps1 - PS script to run on Windows 7/10/11 and Windows Servers systems. Requires PowerShell version 3 or greater

## Usage and Examples

### ncas_collector.ps1

```powershell
PS C:\Users\administrator> Set-ExecutionPolicy -Scope Process Bypass

Execution Policy Change
The execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose you to the security risks described in the
about_Execution_Policies help topic. Do you want to change the execution policy?
[Y] Yes  [N] No  [S] Suspend  [?] Help (default is "Y"): Y
PS C:\Users\administrator> .\ncas_collector.ps1
```

# Contact
To request assistance or schedule an assessment, please contact Cutaway Security at 'info [@] cutawaysecurity.com'.
For information about this project please submit an issue or pull request via GitHub or contact us at 'dev [@] cutawaysecurity.com'.