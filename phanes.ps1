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
    [Parameter(HelpMessage="What is the path to where you have the contents from Phanes stored? Leave empty if current directory.")][string]$path,
    [Parameter(HelpMessage="What flags would you like to run AD Generation with? If empty, will run All.")][string]$flags
)


function upload{

    if (!$flags) # if the flags parameter has no value, assume we're generating everything
    {
        $flags = "-All:$true"
        Write-Host "[+] Flags was empty. Running with full functionality"
    }
    if (!$path)
    {
        $path = "."
    }
    Write-Host "
        
    
    ______ _                           
    | ___ \ |                          
    | |_/ / |__   __ _ _ __   ___  ___ 
    |  __/| '_ \ / _` | '_ \ / _ \/ __|
    | |   | | | | (_| | | | |  __/\__ \
    \_|   |_| |_|\__,_|_| |_|\___||___/
                                           
                                                                             
    "
    Set-Location ./install
    Set-Content ip.txt $dcip
    python install.py 
    # start listeners so we can download the files to DC01
    Set-Location ../
    
    cmd /c ".\nc.exe $dcip 9999 < $path\upload\ad_genUser.ps1"
    cmd /c ".\nc.exe $dcip 9998 < $path\upload\badacl.ps1"
    cmd /c ".\nc.exe $dcip 9997 < $path\upload\ntlmrelay.ps1"
    cmd /c ".\nc.exe $dcip 9996 < $path\upload\vulns.json"
    # connect to the listeners and pass the contents

    Write-Host "[+] Generating AD Network."
    .\sysinternals\psexec.exe \\$dcip -i -h -u "FAKECOMPANY.LOCAL\Administrator" -p "Admin123!" powershell -Command "Import-Module C:\Users\Administrator\Desktop\Scripts\ad_genUser.ps1; Invoke-ADGen $flags" # generate the network
    Write-Host "[+] Restarting machines to implement GPO's."
    Start-Sleep -Seconds 30
    Write-Host "[+] Collecting results."
    .\sysinternals\psexec.exe \\$dcip -i -h -d -u "FAKECOMPANY.LOCAL\Administrator" -p "Admin123!" powershell -Command "cmd /c 'cd C:\Users\Administrator\Desktop\Scripts&ls&.\nc.exe -lvnp 9999 < vulns.json'" # start a listener which will pass the contents of the vulnerability file
    cmd /c ".\nc.exe $dcip 9999 -w 3 > vulns.json" #download the file
    Write-Host "[+] Results collected, generating report."
    pip install python-docx | Out-Null # try and install python-docx incase the user doesnt have it already
    python reportGen.py # generate the report
    Write-Host "[+] Phanes has finished creating. Happy Hacking!"
    Remove-Item ./install/ip.txt
}

upload