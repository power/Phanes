[System.Collections.ArrayList] $FullNames = @('Dennie Drake', 'Cherry Walters', 'Opaline Finley', 'Sharlene Newton', 'Allsun Wade', 'Mersey Owen', 'Ronica Frank', 'Phyllis Watson', 'Agata Atkinson', 'Deeanne Church', 'Mercie Curry', 'Zelda Schaefer', 'Nicol Reyna', 'Kirstin Fields', 'Allyson Zamora', 'Roselin Schultz', 'Brunhilde Bailey', 'Harmonie Dickson', 'Miranda Allen', 'Monica Cox', 'Kimberley Mccarthy', 'Sonya Bentley', 'Joscelin Fox', 'Sharai Peck', 'Peggy Hartman', 'Amy Hanna', 'Joelie Ross', 'Rebeka Case', 'Hanna Kelley', 'Latashia Joseph', 'Bella Mcintosh', 'Fredrika Le', 'Fredi Allen', 'Nonnah Griffin', 'Raphaela Duffy', 'Grete Phelps', 'Sapphira Hull', 'Robinia Mccarthy', 'Marilin Mccann', 'Elizabet West', 'Marya Hickman', 'Emmie Aguirre', 'Bill Frost', 'Teddy Bates', 'Ashlie Salinas', 'Kriste Whitehead', 'Edna Friedman', 'Anabella Hurst', 'Katha Espinoza', 'Lianna Vang', 'Marlane Felix', 'Tabitha Hogan', 'Trix Ward', 'Mirella Mccullough', 'Audry Alexander', 'Janaya Harvey', 'Nalani Jimenez', 'Jacenta Dennis', 'Corine Griffith', 'Esmaria Atkins', 'Morna Coleman', 'Brandise Bentley', 'Willamina Floyd', 'Inesita Rangel', 'Livvie Nicholson', 'Lydia Wheeler', 'Camala Cross', 'Elsey Gross', 'Wallie Oconnell', 'Dru Mccann', 'Minnaminnie Hurley', 'Kesley Wise', 'Bess Herring', 'Bella Anderson', 'Shea Fitzpatrick', 'Ingunna Potter', 'Bobby Humphrey', 'Sabra Turner', 'Angelika Ayers', 'Willyt Quinn', 'Kali Norman', 'Diena Little', 'Donelle Bautista', 'Addi Dean', 'Dniren Bravo', 'Romonda Christian', 'Marney Wells', 'Stephana Flores', 'Zorana Huang', 'Nonnah Hill', 'Tiffani Gardner', 'Dareen Lynn', 'Rosalinda Watkins', 'Enid Haley', 'Coriss Williamson', 'Christy Craig', 'Ulrika Molina', 'Marget Durham', 'Hattie Atkins', 'Caty Allen', 'Cynthie Wallace');
$Global:Passwords = @('candance', 'reese23', 'jungle2', 'ang3ls', 'Sampson', 'arribaperu', '241277', 'rico06', '30091993', 'noah10', 'kenny8', 'isaiah6', '190604', 'Steph', 'bandas', 'cripset', '061300', 'donskie', 'bonez1', 'mike84', 'visage', 'krlita', 'jose2008', 'joelin', 'yellow44', 'lovester', '851002', 'daniel82', 'lexie12', 'newyork16', 'bogdy', 'chance99', 'scholastica', 'mamahku', 'tinjoy', 'smellymelly', '406406', 'linda07', 'jamesallen', 'bluekiss', 'boricua11', 'chi-chi', 'beniamin', 'dante07', 'sweetleaf', 'lllllllllllllll', 'hijito', 'renne', 'tanner10', '140580', 'banana16', '14561456', 'mooka', '747400', '890404', 'DEVILS', 'tristan08', 'jacob2004', 'daddym', 'criselle', 'ella07', 'white7', 'ilove77', 'narutofan1', 'kelsey15', 'molano', 'rule336', 'obrigado', '12021983', 'oreo00', 'kill12', 'Julius', '26091992', '11011992', 'dragoes', '15511551', 'Tequila', 'ganimedes', '260203', '13061988', '281030', 'randy143', 'duckhunt', 'kevinq', 'yeboah', 'sasha05', 'aachen', '092200', 'rickie1', '32147896', 'elshadai', '007james', 'sedruol', '131225', '140604', '15demarzo', 'maccoy', '681990', 'angela4', 'nate24', 'tumay');
$Global:Groups = @('Security', 'Finance', 'Human Resources', 'Marketing', 'Catering', 'IT', 'Research and Development', 'Production');
$Global:Domain = "fakecompany.local"
$Global:Created_Accounts = @();

# All of our variables/constants, mostly just lists for us to pick random values from
function pwGen {
    $temp_var = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 8 | % {[char]$_}) # Takes values as ASCII characters, so any number, lowercase letter or uppercase letter, chooses 8 of them at random and joins them together
    return $temp_var # Returns this value
}
function addUser {
    Param(
        [int]$limit = 20 # By default is 20, if the user wants to make it less then that's up to them
    )
    for ($i = 0; $i -le $limit; $i=$i+1) {
        $full_name = Get-Random -InputObject $Global:FullNames # Choose a random name
        $index = $Global:FullNames.IndexOf($full_name) # Find where it is indexed in the list
        $Global:FullNames.RemoveAt($index) # Remove it so it cannot be chosen again


        $fname,$lname = $full_name.split(" ") # Split the persons name into first & last name to make our SAM username
        $sam_name = ("{0}.{1}" -f ($fname, $lname)).ToLower();

        $password = pwGen # Get a password that meets the complexity requirements
        Write-Output "$sam_name has password $password" # Debugging
        $secure_password = ConvertTo-SecureString -String $password -AsPlainText -Force 
        
        $user_final = @{ # Do the necessary bits and bobs to make our user, we can expand this... https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-aduser?view=windowsserver2022-ps
            Name = $sam_name
            AccountPassword = $secure_password
            Enabled = $true
        }
        New-ADUser @user_final
        $Global:Created_Accounts += $sam_name; # Add their name to one of our global variables so we can mess with them later
        #../../../../../../../../tools/psexec.exe \\COMP01 powershell "Add-LocalGroupMember -Group 'Remote Desktop Users' -Member '$sam_name'"
        
    }
}


function Invoke-ADGen {
    Set-ADDefaultDomainPasswordPolicy -Identity $Global:Domain -LockoutDuration 00:01:00 -LockoutObservationWindow 00:01:00 -ComplexityEnabled $false -ReversibleEncryptionEnabled $False -MinPasswordLength 4 # 1 minute lockout, no complexity and minimum of 4 characters for a password
    addUser -limit 20 # Make 20 accounts
}