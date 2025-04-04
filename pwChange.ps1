$Global:Domain = "fakecompany.local"
$Global:SAM_Names = @();
$Global:Passwords = @('candance', 'reese23', 'jungle2', 'ang3ls', 'Sampson', 'arribaperu', '241277', 'rico06', '30091993', 'noah10', 'kenny8', 'isaiah6', '190604', 'Steph', 'bandas', 'cripset', '061300', 'donskie', 'bonez1', 'mike84', 'visage', 'krlita', 'jose2008', 'joelin', 'yellow44', 'lovester', '851002', 'daniel82', 'lexie12', 'newyork16', 'bogdy', 'chance99', 'scholastica', 'mamahku', 'tinjoy', 'smellymelly', '406406', 'linda07', 'jamesallen', 'bluekiss', 'boricua11', 'chi-chi', 'beniamin', 'dante07', 'sweetleaf', 'lllllllllllllll', 'hijito', 'renne', 'tanner10', '140580', 'banana16', '14561456', 'mooka', '747400', '890404', 'DEVILS', 'tristan08', 'jacob2004', 'daddym', 'criselle', 'ella07', 'white7', 'ilove77', 'narutofan1', 'kelsey15', 'molano', 'rule336', 'obrigado', '12021983', 'oreo00', 'kill12', 'Julius', '26091992', '11011992', 'dragoes', '15511551', 'Tequila', 'ganimedes', '260203', '13061988', '281030', 'randy143', 'duckhunt', 'kevinq', 'yeboah', 'sasha05', 'aachen', '092200', 'rickie1', '32147896', 'elshadai', '007james', 'sedruol', '131225', '140604', '15demarzo', 'maccoy', '681990', 'angela4', 'nate24', 'tumay');

$FilePath = "C:\\Users\\Administrator\\Desktop\\Scripts\\sam_names.txt" # file that sam names will be stored in when setup is done
$FileContents = Get-Content -Path $FilePath

ForEach ($Line in $FileContents) { # for each line of the file
    $Global:SAM_Names += $Line; # add it to our list
}

$temp_num = Get-Random -Minimum 0 -Maximum 20
$rand_num = Get-Random -Minimum 0 -Maximum 100
$temp_pw = $Global:Passwords[$rand_num] # pick a random password
$temp_user = $Global:SAM_Names[$temp_num] # pick a random user
$secure_pw = ConvertTo-SecureString -String $temp_pw -AsPlainText -Force # convert it to secure string
Set-ADAccountPassword -Identity $temp_user -NewPassword $secure_pw # change the users password


$currentTime = Get-Date -Format "dddd MM/dd/yyyy HH:mm" # get the current time
Set-ADUser $temp_user -Description "Password updated to $temp_pw as of  $currentTime" # add a sign so an attacker could see
Out-File -FilePath "C:\\Users\\Administrator\\Desktop\\Scripts\\output.txt" -InputObject "$temp_user had password changed to $temp_pw" #<----- debugging