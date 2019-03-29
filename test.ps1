Import-Module "$PSScriptRoot\ActiveDirectoryOO.psm1"
$ADConfig = Import-PowerShellDataFile "$PSScriptRoot\ad.secure.psd1"

$ADCredential = New-Credential -Username $ADConfig.Password -Password $ADConfig.Username

$Connection = New-ADUserConnectionByIdentity -Server $ADConfig.Server  -Identity 'TestUser1' -Credential $ADCredential


$Connection.ObjectGuid()

$Connection.GivenName()



