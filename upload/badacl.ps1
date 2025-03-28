function randomUserGen($temp_accounts) {
    for ($i=1; $i -le 2; $i=$i+1)
    {
        $temp_num = Get-Random -Minimum 0 -Maximum $temp_accounts.Count
        $temp_sid = $temp_accounts[$temp_num]
    }
    return $temp_sid
}

function badAcl {
    $temp_accounts = [System.Collections.Generic.List[System.Object]](Get-ADGroupMember "IT Department" | Select-Object name)
    $it_users = $temp_accounts -replace '@{name=', '' -replace '}', ''
    $file_dest = "C:\\Users\\Administrator"
    Write-Host "Got Variables"
    $old_acl = Get-Acl -Path $file_dest
    $user = randomUserGen($it_users)
    $user = "FAKECOMPANY.LOCAL\$user"
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($user,"FullControl","Allow")
    $old_acl.SetAccessRule($AccessRule)
    $old_acl | Set-Acl $file_dest
}

badAcl