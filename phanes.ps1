param (
    [string]$DCIP,
    [string]$Path,
    [string]$Flags
)


function upload{

    # Define the share name and folder path
    $ShareName = "Scripts"
    $FolderPath = "$Path"

    # Set NTFS permissions to allow Everyone full control
    $Acl = Get-Acl $FolderPath
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
    $Acl.SetAccessRule($AccessRule)
    Set-Acl -Path $FolderPath -AclObject $Acl

    # Create the SMB share and grant Everyone full access
    New-SmbShare -Name $ShareName -Path $FolderPath -FullAccess Everyone

    Write-Host "SMB share created"
    
    #.\sysinternals\psexec.exe \\$DCIP -i -h -u "FAKECOMPANY.LOCAL\Administrator" -p "Admin123!" powershell -Command "cmd /c 'copy /y \\192.168.18.1\Scripts\upload\* C:\Users\Administrator\\Desktop\Scripts;ls'"
    .\sysinternals\psexec.exe \\$DCIP -i -h -u "FAKECOMPANY.LOCAL\Administrator" -p "Admin123!" powershell -Command 'Import-Module C:\Users\Administrator\Desktop\Scripts\ad_genUser.ps1; Invoke-ADGen $Flags'
    Remove-SmbShare -Name "Scripts" -Force 
    Write-Host "DONE"
    
}

upload
#Write-Host $DCIP" + "$Path" + "$Flags