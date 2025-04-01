<#
.SYNOPSIS
    This script begins the generation of a vulnerable AD network.

.DESCRIPTION
    Phanes is an educational tool designed to help individuals enhance their Active Directory knowledge. The tool intends to do this by generating a realistic & random network in real-time with common AD misconfigurations.

    When using the -flags argument please use ONE of the following:
    -All
        - Generates the network with all features of Phanes
    -Users
        - Simply adds 20 users, no vulnerabilities present.
    -DC
        - Adds vulnerabilities exclusively to DC01
    -COMP
        - Adds vulnerabilities exclusively to COMP01


.EXAMPLE
    PS> .\phanes.ps1 -dcip:"10.10.10.10" -path:"C:\Users\User\Desktop\Phanes" -flags:"-All:$true"
    

.NOTES
    Author: David C
    Version: 1.0
    Last Updated: 04/01/2025

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

    # Define the share name and folder path
    $ShareName = "Scripts"
    $FolderPath = "$path"

    # Set NTFS permissions to allow Everyone full control
    $Acl = Get-Acl $FolderPath
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
    $Acl.SetAccessRule($AccessRule)
    Set-Acl -Path $FolderPath -AclObject $Acl

    # Create the SMB share and grant Everyone full access
    New-SmbShare -Name $ShareName -Path $FolderPath -FullAccess Everyone

    Write-Host "SMB share created"
    
    #.\sysinternals\psexec.exe \\$DCIP -i -h -u "FAKECOMPANY.LOCAL\Administrator" -p "Admin123!" powershell -Command "cmd /c 'copy /y \\192.168.18.1\Scripts\upload\* C:\Users\Administrator\\Desktop\Scripts;ls'"
    .\sysinternals\psexec.exe \\$dcip -i -h -u "FAKECOMPANY.LOCAL\Administrator" -p "Admin123!" powershell -Command "Import-Module C:\Users\Administrator\Desktop\Scripts\ad_genUser.ps1; Invoke-ADGen $flags"
    Remove-SmbShare -Name "Scripts" -Force 
    Write-Host "DONE"
    
}

upload
#Write-Host $DCIP" + "$Path" + "$Flags