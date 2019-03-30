<#
    Do not run in production!
    This tests the ADUserConnection's getter and Setter Methods.
#>
Import-Module "$PSScriptRoot\ActiveDirectoryOO.psm1"

# Import the AD settings
$ADConfig = Import-PowerShellDataFile "$PSScriptRoot\ad.secure.psd1"
$ADCredential = New-Credential -Username $ADConfig.Username -Password $ADConfig.Password



# Create a Connection
$SamAccountName = 'TestUser1'
$User = New-ADUserConnectionByIdentity -Server $ADConfig.Server  -Identity $SamAccountName -Credential $ADCredential




# Check Connection
if($User.ObjectGuid().ToString() -eq '00000000-0000-0000-00000000000000000'){
    throw 'Could Not Create ADUserConnection'
}


# Test Setting a Password
$User.AccountPassword('Password!')

# Test getting and removing AccountExpirationDate
if($User.AccountExpirationDate()){
    $User.AccountExpirationDate($False)
}

# enable the account
$User.Enabled($true)
if($User.Enabled() -ne $true){
    throw 'Failed To Enable Account'
}


# try setting a GivenName
$GivenName = 'Timmy'
$User.GivenName($GivenName)
if($User.GivenName() -ne $GivenName){
    throw 'GivenNamen failed to set or get'
}

# try setting a GivenName
$EmailAddress = 'TestTimmy@Lab.Local'
$User.EmailAddress($EmailAddress)
if($User.EmailAddress() -ne $EmailAddress){
    throw 'EmailAddress failed to set or get'
}


# Get Many Properties At Once
$PropertyCache = $User.Get(@('SamAccountName','EmailAddress','GivenName'))

if($PropertyCache -isnot [hashtable]){
    throw 'Get() Method Did not return a hashtable!'
}
if($PropertyCache.SamAccountName -ne $SamAccountName){
    throw 'Failed to Get SamAccountName'
}
if($PropertyCache.EmailAddress -ne $EmailAddress){
    throw 'Failed to Get EmailAddress'
}
if($PropertyCache.GivenName -ne $GivenName){
    throw 'Failed to Get GivenName'
}






# Memberships
$User.MemberOfGuids()
$User.MemberOf(@('DnsUpdateProxy','Key Admins'))
$User.MemberOf()