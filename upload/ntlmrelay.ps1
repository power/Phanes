$Global:SAM_Names = @();

$FilePath = "C:\\Users\\Administrator.FAKECOMPANY\\Desktop\\sam_names.txt" # file that sam names will be stored in when setup is done
$FileContents = Get-Content -Path $FilePath

ForEach ($Line in $FileContents) { # for each line of the file
    $Global:SAM_Names += $Line; # add it to our list
}

function randomUserGen($temp_accounts) {
    $temp_num = Get-Random -Minimum 0 -Maximum $temp_accounts.Count
    $temp_sid = $temp_accounts[$temp_num]
    return $temp_sid
}


function configureSmb {
    $SharePath = "C:\Inconspicious Share"
    $ShareName = "InconspiciousShare"
    New-Item -Path $SharePath -ItemType Directory | Out-Null
    New-SmbShare -Name $ShareName -Path $SharePath
    #Create SMB server

    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name RequireSecuritySignature -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name RequireSecuritySignature -Value 0
    # Disable SMB Signing

    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel -Value 0
    # Enable NTLM auth

    Set-SmbServerConfiguration -EncryptData $false -Force
    Set-SmbServerConfiguration -RejectUnencryptedAccess $false -Force

    $acl = Get-Acl $SharePath

    # Create access rules
    $ruleEveryone = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $ruleGuest = New-Object System.Security.AccessControl.FileSystemAccessRule("Guest", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $ruleAnonymous = New-Object System.Security.AccessControl.FileSystemAccessRule("ANONYMOUS LOGON", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")

    # Apply rules
    $acl.SetAccessRule($ruleEveryone)
    $acl.SetAccessRule($ruleGuest)
    $acl.SetAccessRule($ruleAnonymous)
    Set-Acl -Path $SharePath -AclObject $acl

    # Set SMB share permissions
    Grant-SmbShareAccess -Name $ShareName -AccountName "Everyone" -AccessRight Full -Force
    Grant-SmbShareAccess -Name $ShareName -AccountName "Guest" -AccessRight Full -Force
    Grant-SmbShareAccess -Name $ShareName -AccountName "ANONYMOUS LOGON" -AccessRight Full -Force


    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name EveryoneIncludesAnonymous -Value 1

    # Disable 'Restrict anonymous access to Named Pipes and Shares'
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name RestrictNullSessAccess -Value 0

    # Allow anonymous access to the specific share
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name NullSessionShares -Value "InconspiciousShare"
    
    $temp_user = randomUserGen($Global:SAM_Names)
    # Get a list of folders and files
    $acct = New-Object System.Security.Principal.NTAccount("FAKECOMPANY.LOCAL", "$temp_user")
    $ItemList = Get-ChildItem -Path "C:\Inconspicious Share" -Recurse;

    # Iterate over files/folders
    foreach ($Item in $ItemList) {
        $Acl = $null; # Reset the $Acl variable to $null
        $Acl = Get-Acl -Path $Item.FullName; # Get the ACL from the item
        $Acl.SetOwner($acct); # Update the in-memory ACL
        Set-Acl -Path $Item.FullName -AclObject $Acl;  # Set the updated ACL on the target item
    }
    $acl = Get-ACL -Path "C:\Inconspicious Share"
    $acl.SetOwner($acct)
    Set-Acl -Path "C:\Inconspicious Share" -AclObject $acl
}

configureSmb