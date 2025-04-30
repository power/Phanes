param (
    [switch]$All,
    [switch]$Users,
    [switch]$DC,
    [switch]$COMP
)

Import-Module C:\Users\Administrator\Desktop\Scripts\PowerView.ps1

[System.Collections.ArrayList] $FullNames = @('Dennie Drake', 'Cherry Walters', 'Opaline Finley', 'Sharlene Newton', 'Allsun Wade', 'Mersey Owen', 'Ronica Frank', 'Phyllis Watson', 'Agata Atkinson', 'Deeanne Church', 'Mercie Curry', 'Zelda Schaefer', 'Nicol Reyna', 'Kirstin Fields', 'Allyson Zamora', 'Roselin Schultz', 'Brunhilde Bailey', 'Harmonie Dickson', 'Miranda Allen', 'Monica Cox', 'Kimberley Mccarthy', 'Sonya Bentley', 'Joscelin Fox', 'Sharai Peck', 'Peggy Hartman', 'Amy Hanna', 'Joelie Ross', 'Rebeka Case', 'Hanna Kelley', 'Latashia Joseph', 'Bella Mcintosh', 'Fredrika Le', 'Fredi Allen', 'Nonnah Griffin', 'Raphaela Duffy', 'Grete Phelps', 'Sapphira Hull', 'Robinia Mccarthy', 'Marilin Mccann', 'Elizabet West', 'Marya Hickman', 'Emmie Aguirre', 'Bill Frost', 'Teddy Bates', 'Ashlie Salinas', 'Kriste Whitehead', 'Edna Friedman', 'Anabella Hurst', 'Katha Espinoza', 'Lianna Vang', 'Marlane Felix', 'Tabitha Hogan', 'Trix Ward', 'Mirella Mccullough', 'Audry Alexander', 'Janaya Harvey', 'Nalani Jimenez', 'Jacenta Dennis', 'Corine Griffith', 'Esmaria Atkins', 'Morna Coleman', 'Brandise Bentley', 'Willamina Floyd', 'Inesita Rangel', 'Livvie Nicholson', 'Lydia Wheeler', 'Camala Cross', 'Elsey Gross', 'Wallie Oconnell', 'Dru Mccann', 'Minnaminnie Hurley', 'Kesley Wise', 'Bess Herring', 'Bella Anderson', 'Shea Fitzpatrick', 'Ingunna Potter', 'Bobby Humphrey', 'Sabra Turner', 'Angelika Ayers', 'Willyt Quinn', 'Kali Norman', 'Diena Little', 'Donelle Bautista', 'Addi Dean', 'Dniren Bravo', 'Romonda Christian', 'Marney Wells', 'Stephana Flores', 'Zorana Huang', 'Nonnah Hill', 'Tiffani Gardner', 'Dareen Lynn', 'Rosalinda Watkins', 'Enid Haley', 'Coriss Williamson', 'Christy Craig', 'Ulrika Molina', 'Marget Durham', 'Hattie Atkins', 'Caty Allen', 'Cynthie Wallace');
$Global:Groups = @('Security', 'Finance', 'Human Resources', 'Marketing', 'Catering', 'IT', 'Research and Development', 'Production');
$Global:Passwords = @('candance', 'reese23', 'jungle2', 'ang3ls', 'Sampson', 'arribaperu', '241277', 'rico06', '30091993', 'noah10', 'kenny8', 'isaiah6', '190604', 'Steph', 'bandas', 'cripset', '061300', 'donskie', 'bonez1', 'mike84', 'visage', 'krlita', 'jose2008', 'joelin', 'yellow44', 'lovester', '851002', 'daniel82', 'lexie12', 'newyork16', 'bogdy', 'chance99', 'scholastica', 'mamahku', 'tinjoy', 'smellymelly', '406406', 'linda07', 'jamesallen', 'bluekiss', 'boricua11', 'chi-chi', 'beniamin', 'dante07', 'sweetleaf', 'lllllllllllllll', 'hijito', 'renne', 'tanner10', '140580', 'banana16', '14561456', 'mooka', '747400', '890404', 'DEVILS', 'tristan08', 'jacob2004', 'daddym', 'criselle', 'ella07', 'white7', 'ilove77', 'narutofan1', 'kelsey15', 'molano', 'rule336', 'obrigado', '12021983', 'oreo00', 'kill12', 'Julius', '26091992', '11011992', 'dragoes', '15511551', 'Tequila', 'ganimedes', '260203', '13061988', '281030', 'randy143', 'duckhunt', 'kevinq', 'yeboah', 'sasha05', 'aachen', '092200', 'rickie1', '32147896', 'elshadai', '007james', 'sedruol', '131225', '140604', '15demarzo', 'maccoy', '681990', 'angela4', 'nate24', 'tumay');
$Global:Domain = "fakecompany.local"
$Global:Created_Accounts = @();
$Global:Created_Groups = @();
$Global:temp_pass = @();

# All of our variables/constants, mostly just lists for us to pick random values from

function jsonify($name, $par, $value){
    $a = Get-Content 'C:\Users\Administrator\Desktop\Scripts\vulns.json' -raw | ConvertFrom-Json 
    $a.vulns | ForEach-Object { 
        if($_."Name" -eq $name) # if the current vuln's name equals the one passed to the function
        {
            $_.$par = $value # set the parameter under that object to equal the value e.g. Kerberoasting is the object, SID1 is the parameter and bob.rob is the value
        }
    }
    $a | ConvertTo-Json -depth 32| set-content 'C:\Users\Administrator\Desktop\Scripts\vulns.json' # output the value, convert to json then save to the same file we read from at the start of the function so this acts as an overwrite
}
function randomUserGen($temp_accounts) {
    $temp_num = Get-Random -Minimum 0 -Maximum $temp_accounts.Count
    $temp_sid = $temp_accounts[$temp_num]
    return $temp_sid
}

function strongPwGen {
    $temp_var = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 8 | ForEach-Object {[char]$_}) # Takes values as ASCII characters, so any number, lowercase letter or uppercase letter, chooses 8 of them at random and joins them together
    return $temp_var # Returns this value
}

function weakPwGen {
    $temp_var = -join ((97..122) | Get-Random -Count 5 | ForEach-Object {[char]$_}) # just lowercase characters
    return $temp_var
}

function middlePwGen {
    $temp_num = Get-Random -Minimum 0 -Maximum 10 # random number gen
    if ($temp_num -le 5){
        $temp_var = -join ((48..57) + (65..90) | Get-Random -Count 7 | ForEach-Object {[char]$_}) # uppercase characters + numbers
    }
    else {
      $temp_var = -join ((48..57) + (97..122) | Get-Random -Count 7 | ForEach-Object {[char]$_})  # or lowercase characters + numbers
    }
    return $temp_var
}
function addUser {

    # Simple Users
    $policyParams = @{
        Name = "weakPasswordPolicy" # Identifiable name
        ComplexityEnabled = $false
        LockoutDuration = "00:01:00" # how long are you locked out for
        LockoutObservationWindow = "00:01:00" # how long are we marking incorrect passwords over
        LockoutThreshold = "0"
        MaxPasswordAge = "365.00:00:00" # how long before it needs to be changed
        MinPasswordAge = "00.00:30:00"
        MinPasswordLength = "1"
        PasswordHistoryCount = "1"
        Precedence = "1" # what takes priority
        ReversibleEncryptionEnabled = $true
        ProtectedFromAccidentalDeletion = $false
    }
    New-ADFineGrainedPasswordPolicy @policyParams # create it
    Add-ADFineGrainedPasswordPolicySubject weakPasswordPolicy -Subjects "Pre Merger" # assign our group to it
    
    for ($i = 0; $i -le 7; $i=$i+1) {
        $full_name = Get-Random -InputObject $Global:FullNames # Choose a random name
        $index = $Global:FullNames.IndexOf($full_name) # Find where it is indexed in the list
        $Global:FullNames.RemoveAt($index) # Remove it so it cannot be chosen again


        $fname,$lname = $full_name.split(" ") # Split the persons name into first & last name to make our SAM username
        $sam_name = ("{0}.{1}" -f ($fname, $lname)).ToLower();  
        $password = weakPwGen
        Write-Output "[+] $sam_name has weak password $password"
        $secure_password = ConvertTo-SecureString -String $password -AsPlainText -Force
        
        $user_final = @{
            Name = $sam_name
            DisplayName = ("{0} {1}" -f ($fname, $lname))
            AccountPassword = $secure_password
            Enabled = $true
        }
        New-ADUser @user_final
        $Global:Created_Accounts += $sam_name;
        Add-ADGroupMember -Identity "Pre Merger" -Members $sam_name
    }


    # Medium Users
    $policyParams = @{
        Name = "mediumPasswordPolicy"
        ComplexityEnabled = $false
        LockoutDuration = "00:30:00"
        LockoutObservationWindow = "00:30:00"
        LockoutThreshold = "5"
        MaxPasswordAge = "90.00:00:00"
        MinPasswordAge = "00.00:30:00"
        MinPasswordLength = "5"
        PasswordHistoryCount = "3"
        Precedence = "2"
        ReversibleEncryptionEnabled = $false
        ProtectedFromAccidentalDeletion = $true
    }
    New-ADFineGrainedPasswordPolicy @policyParams
    Add-ADFineGrainedPasswordPolicySubject mediumPasswordPolicy -Subjects "Post Merger"
    
    for ($i = 0; $i -le 7; $i=$i+1) {
        $full_name = Get-Random -InputObject $Global:FullNames # Choose a random name
        $index = $Global:FullNames.IndexOf($full_name) # Find where it is indexed in the list
        $Global:FullNames.RemoveAt($index) # Remove it so it cannot be chosen again


        $fname,$lname = $full_name.split(" ") # Split the persons name into first & last name to make our SAM username
        $sam_name = ("{0}.{1}" -f ($fname[0], $lname)).ToLower();  
        $password = middlePwGen
        if ($i -eq 3)
        {
            $Global:temp_pass = "$sam_name : $password"
            Out-File -FilePath C:\Users\Administrator\Desktop\Scripts\login_details.txt -InputObject $Global:temp_pass -Encoding ascii
        }
        Write-Output "[+] $sam_name has middle password $password"
        $secure_password = ConvertTo-SecureString -String $password -AsPlainText -Force
        
        $user_final = @{
            Name = $sam_name
            DisplayName = ("{0} {1}" -f ($fname, $lname))
            AccountPassword = $secure_password
            Enabled = $true
        }
        New-ADUser @user_final
        $Global:Created_Accounts += $sam_name;
        Add-ADGroupMember -Identity "Post Merger" -Members $sam_name
    }

    # Post Post Merger
    $policyParams = @{
        Name = "strongPasswordPolicy"
        ComplexityEnabled = $true
        LockoutDuration = "02:00:00"
        LockoutObservationWindow = "02:00:00"
        LockoutThreshold = "3"
        MaxPasswordAge = "30.00:00:00"
        MinPasswordAge = "00.00:30:00"
        MinPasswordLength = "7"
        PasswordHistoryCount = "5"
        Precedence = "3"
        ReversibleEncryptionEnabled = $false
        ProtectedFromAccidentalDeletion = $true
    }
    New-ADFineGrainedPasswordPolicy @policyParams
    Add-ADFineGrainedPasswordPolicySubject strongPasswordPolicy -Subjects "Post Post Merger"
    
    for ($i = 0; $i -le 6; $i=$i+1) {
        $full_name = Get-Random -InputObject $Global:FullNames # Choose a random name
        $index = $Global:FullNames.IndexOf($full_name) # Find where it is indexed in the list
        $Global:FullNames.RemoveAt($index) # Remove it so it cannot be chosen again


        $fname,$lname = $full_name.split(" ") # Split the persons name into first & last name to make our SAM username
        $sam_name = ("{0}.{1}" -f ($fname[0], $lname)).ToLower();  
        $password = strongPwGen
        if ($i -eq 3)
        {
            $creds = "$sam_name : $password"
            Out-File -FilePath C:\Users\Administrator\Desktop\Scripts\relay_creds.txt -InputObject $creds -Encoding ascii
        }
        Write-Output "[+] $sam_name has strong password $password"
        $secure_password = ConvertTo-SecureString -String $password -AsPlainText -Force
        
        $user_final = @{
            Name = $sam_name
            DisplayName = ("{0} {1}" -f ($fname, $lname))
            AccountPassword = $secure_password
            Enabled = $true
        }
        New-ADUser @user_final
        $Global:Created_Accounts += $sam_name;
        Add-ADGroupMember -Identity "Post Post Merger" -Members $sam_name
    }

    Out-File -FilePath "C:\\Users\\Administrator\\Desktop\\Scripts\\sam_names.txt" -InputObject $Global:Created_Accounts # put the entire list into a text file
}

function asRepRoasting {
    $temp_num = Get-Random -Minimum 1 -Maximum 10
    $temp_accounts = [System.Collections.Generic.List[System.Object]]($Global:Created_Accounts)
    if ($temp_num -le 5)
    {
        jsonify "ASREP" "Status" "False"
        jsonify "ASREP" "SID1" "None"
    }
    else { # if we hit our percentage
        jsonify "ASREP" "Status" "True"
        for ($i=1; $i -le 3; $i=$i+1) # for 2 users
        {
            $temp_sid = randomUserGen($temp_accounts)
            $temp_accounts.RemoveAt($temp_accounts.IndexOf($temp_sid)) # remove the user from our temporary list so we don't pick them twice
            Write-Output "[+] $temp_sid is rep-roastable"
            Get-ADUser -Identity $temp_sid | Set-ADAccountControl -DoesNotRequirePreAuth:$true # get the user and disable pre-authentication
            $temp_accounts.Remove($temp_num) | Out-Null
            jsonify "ASREP" "SID$i" $temp_sid        
        }
    }


}

function unconstrainedDelegation {
    $temp_num = Get-Random -Minimum 0 -Maximum 10
    if ($temp_num -le 5)
    {
        Write-Output "[-] COMP01 is not vulnerable to unconstrained delegation"
        jsonify "unconstrainedDelegation" "Status" "False"
        jsonify "unconstrainedDelegation" "SID1" "None"
    }
    else {
        Set-ADAccountControl -Identity "COMP01$" -TrustedForDelegation $true # allow the machine to be delegated to
        $temp_user = randomUserGen($Global:Created_Accounts)
        Write-Output "[+] COMP01 is vulnerable to unconstrained delegation as $temp_user"
        C:\Users\Administrator\Desktop\Scripts\psexec.exe \\comp01 -i -h -u "FAKECOMPANY.LOCAL\Administrator" -p "Admin123!" powershell -Command "Add-LocalGroupMember -Group 'Administrators' -Member $temp_user@fakecompany.local | Out-Null" # add the user as a local admin so they can get the tgt's
        Enter-PSSession COMP01 # RDP into the computer to generate the ticket 
        hostname | Out-Null # run a command for certainty
        Exit-PSSession # close the session
        jsonify "unconstrainedDelegation" "SID1" "$temp_user"
        jsonify "unconstrainedDelegation" "Status" "True"    
        }
}

function addGroups {
    for ($i=0; $i -le 7; $i=$i+1)
    {
        $temp_group = $Global:Groups[$i]
        $temp_num = Get-Random -Minimum 0 -Maximum 10
        if ($temp_num -le 5)
        {
            New-ADGroup -Name "$temp_group Department" -SamAccountName ("{0} {1}" -f ($temp_group, "Department")) -GroupCategory Security -GroupScope Global -DisplayName "$temp_group" -Path "CN=Users,DC=Fakecompany,DC=Local" -Description "A group for $temp_group members!" 
            $sam_name = ("{0} {1}" -f ($temp_group, "Department"))
            $Global:Created_Groups += $sam_name
            #Write-Output "[+] Group created with SAM: $sam_name"
        }
        else 
        {
            New-ADGroup -Name "$temp_group Department" -SamAccountName ("{0} {1}" -f ($temp_group, "Department")) -GroupCategory Distribution -GroupScope Global -DisplayName "$temp_group" -Path "CN=Users,DC=Fakecompany,DC=Local" -Description "A group for $temp_group members!" 
            $sam_name = ("{0} {1}" -f ($temp_group, "Department"))
            $Global:Created_Groups += $sam_name
            #Write-Output "[+] Group created with SAM: $sam_name"
        }
    }

    $counter = 0
    $temp_group = $Global:Created_Groups[$counter]
    $temp_accounts = [System.Collections.Generic.List[System.Object]]($Global:Created_Accounts)
    for ($i=0; $i -le 20; $i=$i+1)
    {
        $temp_account = randomUserGen($temp_accounts)
        if ($i % 3 -eq 0) # if the number is divisible by 3, move onto the next group
        {
            $counter=$counter+1 
            $temp_group = $Global:Created_Groups[$counter]# pick a new group
            Add-ADGroupMember -Identity $temp_group -Members $temp_account # add a user to that group
        }
        else 
        {
            Add-ADGroupMember -Identity $temp_group -Members $temp_account # continue adding to the same group
            
        }
        Add-ADGroupMember -Identity "Remote Desktop Users" -Members $temp_account # allow them to remotely logged into
        Write-Output (-join("[+] Added ", $temp_account, " into group $temp_group")) # needs to be done this way because of the different strings
        $temp_accounts.RemoveAt($temp_accounts.IndexOf($temp_account)) # remove the user from the temporary list 
    }
}

function dcSync {
    $num = Get-Random -Minimum 0 -Maximum 10
    if ($num -gt 5)
    {
        $temp_accounts = [System.Collections.Generic.List[System.Object]]($Global:Created_Accounts)
        $it_users = [System.Collections.Generic.List[System.Object]](Get-ADGroupMember "IT Department" | Select-Object name) # get each user's username that is in the IT department
        $it_users = $temp_accounts -replace '@{name=', '' -replace '}', '' # strip the string for the extra stuff
        $num = Get-Random -Minimum 0 -Maximum 2
        $vuln_user = $it_users[$num] # pick a random user from the IT department group
        Add-ObjectACL -PrincipalIdentity $it_users[$num] -Rights DCSync # use powerview's functionality to give them DCSync rights
        $temp_sid = randomUserGen($temp_accounts)
        Add-ObjectACL -PrincipalIdentity $temp_sid -TargetIdentity $vuln_user -Rights All # give another user genericall over the dcsync user
        Write-Host "[+] $vuln_user can perform DCSync attack."
        jsonify "dcSync" "SID1" "$vuln_user"        
    }
    else {
        jsonify "dcSync" "SID1" "None"
        Write-Host "[-] DCSync vulnerability not present."
    }
}

function kerberoasting {
    $num = Get-Random -Minimum 0 -Maximum 10
    $temp_accounts = [System.Collections.Generic.List[System.Object]]($Global:Created_Accounts)
    if ($num -gt 5)
    {
        for ($i = 1; $i -le 2; $i++)
        {
            $temp_sam = randomUserGen($temp_accounts)
            $temp_accounts.RemoveAt($temp_accounts.IndexOf($temp_sam))
            setspn -a dc01/$temp_sam.fakecompany.local fakecompany.local\$temp_sam | Out-Null # give the user an SPN so it can be kerberoasted
            Write-Host "[+] dc01/$temp_sam.$Global:Domain can be Kerberoasted"
            jsonify "Kerberoasting" "SID$i" $temp_sam             
        }
       
    }
    else
    {
        jsonify "Kerberoasting" "SID1" "None"
        jsonify "Kerberoasting" "SID2" "None"
        Write-Host "[-] No Kerberoastable objects on the DC."
    }
}

function badAcl {
    #C:\Users\Administrator\Desktop\Scripts\psexec.exe \\comp01 powershell -Command "C:\Users\Administrator\Desktop\badacl.ps1"
    $num = Get-Random -Minimum 0 -Maximum 10
    if ($num -le 6)
    {
        Write-Host "[-] BadACL's not present."
        jsonify "badACL" "Status" "False"
    }
    else {
        Write-Host "[+] Implementing BadACL Vulnerability"
        $Params = @{ # create a smb share that points to this folder and gives any Domain Admin full rwx access
            Name = "COMP01_Files"
            Path = "C:\Users\Administrator\Desktop\Scripts"
            FullAccess = 'FAKECOMPANY.LOCAL\Domain Admins'
        }
        New-SmbShare @Params | Out-Null
        C:\Users\Administrator\Desktop\Scripts\psexec.exe \\comp01 -u "FAKECOMPANY.LOCAL\Administrator" -p "Admin123!" powershell -Command "cmd /c 'copy /y \\192.168.18.149\COMP01_Files\badacl.ps1 C:\\Users\Administrator.FAKECOMPANY\\Desktop'" | Out-Null # copy the powershell script across
        C:\Users\Administrator\Desktop\Scripts\psexec.exe \\comp01 -u "FAKECOMPANY.LOCAL\Administrator" -p "Admin123!" powershell -Command "cmd /c 'copy /y \\192.168.18.149\COMP01_Files\login_details.txt C:\\Users\Administrator\\Desktop'" | Out-Null # copy the file to be found from badacl
        Remove-Item C:\Users\Administrator\Desktop\Scripts\login_details.txt # remove the artefact 
        C:\Users\Administrator\Desktop\Scripts\psexec.exe \\comp01 -u "FAKECOMPANY.LOCAL\Administrator" -p "Admin123!" powershell -Command "C:\Users\Administrator.FAKECOMPANY\Desktop\badacl.ps1" | Out-Null #run the powershell script
        Remove-SmbShare -Name "COMP01_Files" -Force | Out-Null # remove the smb share so it can't be enumerated
        Write-Host "[+] BadACL's implemented."
        jsonify "badACL" "Status" "True"       
    }
}

function ntlmRelay {
    $num = Get-Random -Minimum 0 -Maximum 10
    $Params = @{
        Name = "COMP01_Files"
        Path = "C:\Users\Administrator\Desktop\Scripts"
        FullAccess = 'FAKECOMPANY.LOCAL\Domain Admins'
    }
    New-SmbShare @Params | Out-Null
    if ($num -le 4)
    {
        Write-Host "[+] Implementing anonymous SMB share"
        C:\Users\Administrator\Desktop\Scripts\psexec.exe \\comp01 -u "FAKECOMPANY.LOCAL\Administrator" -p "Admin123!" powershell -Command "cmd /c 'copy /y \\192.168.18.149\COMP01_Files\ntlmrelay.ps1 C:\\Users\Administrator.FAKECOMPANY\\Desktop'" | Out-Null
        C:\Users\Administrator\Desktop\Scripts\psexec.exe \\comp01 -u "FAKECOMPANY.LOCAL\Administrator" -p "Admin123!" powershell -Command "cmd /c 'copy /y \\192.168.18.149\COMP01_Files\sam_names.txt C:\\Users\Administrator.FAKECOMPANY\\Desktop'" | Out-Null # needed for ntlmrelay to work
        C:\Users\Administrator\Desktop\Scripts\psexec.exe \\comp01 -u "FAKECOMPANY.LOCAL\Administrator" -p "Admin123!" -s powershell -Command "C:\Users\Administrator.FAKECOMPANY\Desktop\ntlmrelay.ps1 -SMB:$true" | Out-Null # run ntlmrelay script but just implement the SMB share for basic enumeration
        Write-Host "[-] NTLM Relay not present."
        jsonify "ntlmRelay" "Status" "False"
    }
    else {
        Write-Host "[+] Implementing NTLM Relay vulnerability."
        C:\Users\Administrator\Desktop\Scripts\psexec.exe \\comp01 -u "FAKECOMPANY.LOCAL\Administrator" -p "Admin123!" powershell -Command "cmd /c 'copy /y \\192.168.18.149\COMP01_Files\ntlmrelay.ps1 C:\\Users\Administrator.FAKECOMPANY\\Desktop'" | Out-Null
        C:\Users\Administrator\Desktop\Scripts\psexec.exe \\comp01 -u "FAKECOMPANY.LOCAL\Administrator" -p "Admin123!" powershell -Command "cmd /c 'copy /y \\192.168.18.149\COMP01_Files\sam_names.txt C:\\Users\Administrator.FAKECOMPANY\\Desktop'" | Out-Null
        $fp = "C:\Users\Administrator\Desktop\Scripts\relay_creds.txt" # file that sam names will be stored in when setup is done
        $FileContents = Get-Content -Path $fp # get the credentials 
        $sam,$password = $FileContents.Split(":").Trim() # store the username and password
        C:\Users\Administrator\Desktop\Scripts\psexec.exe \\comp01 -i -h -u "FAKECOMPANY.LOCAL\Administrator" -p "Admin123!" powershell -Command "Add-LocalGroupMember -Group 'Administrators' -Member $sam@fakecompany.local | Out-Null" # make them a local admin so we can simulate them being on the machine
        cmdkey /add:comp01 /user:$sam /pass:$password # allow us to automate logging into rdp
        Start-Sleep -Seconds 5
        mstsc /v:comp01 # log into rdp
        C:\Users\Administrator\Desktop\Scripts\psexec.exe \\comp01 -u "FAKECOMPANY.LOCAL\Administrator" -p "Admin123!" powershell -Command "cmd /c 'copy /y \\192.168.18.149\COMP01_Files\relay_creds.txt C:\\Users\Administrator.FAKECOMPANY\\Desktop'" | Out-Null #copy the creds so they can be used when creating the service
        C:\Users\Administrator\Desktop\Scripts\psexec.exe \\comp01 -u "FAKECOMPANY.LOCAL\Administrator" -p "Admin123!" -s powershell -Command "C:\Users\Administrator.FAKECOMPANY\Desktop\ntlmrelay.ps1 -All:$true" | Out-Null # generate the smb share and the ntlm trigger
        Write-Host "[+] NTLM Relay implemented."
        jsonify "ntlmRelay" "Status" "True"
    }
    Remove-SmbShare -Name "COMP01_Files" -Force | Out-Null
}

function secretsDump {
    $temp_accounts = [System.Collections.Generic.List[System.Object]]($Global:Created_Accounts)
    Enable-PSRemoting
    Install-PackageProvider -Name NuGet -Force
    Install-Module -Name PSPrivilege -Force
    Import-Module PSPrivilege
    for ($i = 1; $i -le 3; $i++)
    {
        $temp_user = randomUserGen $temp_accounts
        $sid = (Get-ADUser $temp_user).Sid
        Add-WindowsRight -Name SeBackupPrivilege -Account $sid -ComputerName COMP01 # doesnt seem to add the rights
        $temp_accounts.RemoveAt($temp_accounts.IndexOf($temp_user))
        Write-Host "[+] $temp_user has SeBackupPrivilege"
        jsonify "secretsDump" "SID$I" $temp_user
    } 
}

function Invoke-ADGen($All, $Users) {
    Set-ADDefaultDomainPasswordPolicy -Identity $Global:Domain -LockoutDuration 00:01:00 -LockoutObservationWindow 00:01:00 -ComplexityEnabled $false -ReversibleEncryptionEnabled $False -MinPasswordLength 4 # 1 minute lockout, no complexity and minimum of 4 characters for a password
    Get-ADGroup "Domain Users" -Properties Description | New-ADGroup -Name "Pre Merger" -SamAccountName "Pre Merger" -GroupCategory Distribution -PassThru | Out-Null
    Get-ADGroup "Domain Users" -Properties Description | New-ADGroup -Name "Post Merger" -SamAccountName "Post Merger" -GroupCategory Distribution -PassThru | Out-Null
    Get-ADGroup "Domain Users" -Properties Description | New-ADGroup -Name "Post Post Merger" -SamAccountName "Post Post Merger" -GroupCategory Security -PassThru | Out-Null
    if ($All){
        addUser # Make 20 accounts
        #Start-Sleep -Seconds 2
        asRepRoasting
        #Start-Sleep -Seconds 2
        unconstrainedDelegation
        #Start-Sleep -Seconds 2
        addGroups
        #Start-Sleep -Seconds 2
        #secretsDump
        dcSync  
        kerberoasting  
        badAcl    
        ntlmRelay
    }
    elseif ($Users)
    {
        addUser # Make 20 accounts    
        addGroups    
    }
    elseif ($DC)
    {
        addUser
        addGroups
        dcSync
        kerberoasting
        gpo_abuse
        secretsDump
    }
    elseif ($COMP) # make case for if dc + comp
    {
        addUser
        addGroups
        unconstrainedDelegation
        badAcl
        ntlmRelay
    }
    else {
        Write-Host "No flags specified, script not ran."
    }
}
