function randomUserGen($temp_accounts) {
    $temp_num = Get-Random -Minimum 0 -Maximum $temp_accounts.Count
    $temp_sid = $temp_accounts[$temp_num]
    return $temp_sid
}

function badAcl {
    $temp_accounts = [System.Collections.Generic.List[System.Object]](Get-ADGroupMember "IT Department" | Select-Object name)
    $it_users = $temp_accounts -replace '@{name=', '' -replace '}', ''
    $file_dest = "C:\\Users\\Administrator"
    # define our variables
    $old_acl = Get-Acl -Path $file_dest
    $user = randomUserGen($it_users)
    $user = "FAKECOMPANY.LOCAL\$user"
    # generate necessary information
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($user,"FullControl","Allow") #create the rule to give the user full control over the object
    $old_acl.SetAccessRule($AccessRule) # set the rule inside of the ACL
    $old_acl | Set-Acl $file_dest # set the ACL
}

badAcl