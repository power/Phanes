function randomUserGen($temp_accounts) {
    $temp_num = Get-Random -Minimum 0 -Maximum $temp_accounts.Count
    $temp_sid = $temp_accounts[$temp_num]
    return $temp_sid
}

function badAcl {
    $temp_accounts = [System.Collections.Generic.List[System.Object]](Get-ADGroupMember "IT Department" | Select-Object name)
    $it_users = $temp_accounts -replace '@{name=', '' -replace '}', ''
    $user = randomUserGen($it_users)
    $user = "FAKECOMPANY.LOCAL\$user"
    $base_path = "C:\\Users\\Administrator"
    $ItemList = Get-ChildItem -Path $base_path -Recurse;
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($user,"FullControl","Allow") #create the rule to give the user full control over the object
    
    
    foreach ($Item in $ItemList) {
        $Acl = Get-Acl -Path $Item.FullName; # Get the ACL from the item
        $Acl.SetAccessRule($AccessRule); # Update the in-memory ACL
        $Acl | Set-Acl $Item.FullName;  # Set the updated ACL on the target item
    }
    # define our variables
    $old_acl = Get-Acl -Path $base_path
    $old_acl.SetAccessRule($AccessRule) # set the rule inside of the ACL
    $old_acl | Set-Acl $base_path # set the ACL
}

badAcl