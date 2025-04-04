<#
.SYNOPSIS
    This script begins the generation of a vulnerable AD network.

.DESCRIPTION
    Phanes is an educational tool designed to help individuals enhance their Active Directory knowledge. The tool intends to do this by generating a realistic & random network in real-time with common AD misconfigurations.

    When using the -flags argument, please use ONE of the following:
    -All
        - Generates the network with all features of Phanes.
    -Users
        - Simply adds 20 users, no vulnerabilities present.
    -DC
        - Adds vulnerabilities exclusively to DC01.
    -COMP
        - Adds vulnerabilities exclusively to COMP01.

    Example Usage:
    .\phanes.ps1 -dcip:"10.10.10.10" -path:"C:\Users\User\Desktop\Phanes" -flags:"-All:$true"
.EXAMPLE
    PS> .\phanes.ps1 -dcip:"10.10.10.10" -path:"C:\Users\User\Desktop\Phanes" -flags:"-All:$true"
    

.NOTES
    Author: David C
    Version: 1.0
    Last Updated: 01/04/2025

#>

param (
    [Parameter(Mandatory,HelpMessage="What is the Domain Controller's IP address?")][string]$dcip,
    [Parameter(Mandatory,HelpMessage="What is the path to where you have the contents from Phanes stored?")][string]$path,
    [Parameter(HelpMessage="What flags would you like to run AD Generation with? If empty, will run All.")][string]$flags
)


function upload{

    if (!$flags)
    {
        $flags = "-All:$true"
        Write-Host "[+] Flags was empty. Running with full functionality"
    }
    Write-Host "
        
    
    ______ _                           
    | ___ \ |                          
    | |_/ / |__   __ _ _ __   ___  ___ 
    |  __/| '_ \ / _` | '_ \ / _ \/ __|
    | |   | | | | (_| | | | |  __/\__ \
    \_|   |_| |_|\__,_|_| |_|\___||___/
                                           
                                                                             
    "
    Write-Host "[+] Generating AD Network"
    .\sysinternals\psexec.exe \\$dcip -i -h -u "FAKECOMPANY.LOCAL\Administrator" -p "Admin123!" powershell -Command "Import-Module C:\Users\Administrator\Desktop\Scripts\ad_genUser.ps1; Invoke-ADGen $flags"
    Write-Host "[+] Collecting results."
    .\sysinternals\psexec.exe \\$dcip -i -h -d -u "FAKECOMPANY.LOCAL\Administrator" -p "Admin123!" powershell -Command "cmd /c 'cd C:\Users\Administrator\Desktop\Scripts&ls&.\nc.exe -lvnp 9999 < vulns.json'"
    cmd /c ".\nc.exe $dcip 9999 -w 3 > vulns.json"
    Write-Host "[+] Results collected, generating report."
    python reportGen.py
    Write-Host "[+] Phanes has finished creating. Happy Hacking!"
    
}

upload