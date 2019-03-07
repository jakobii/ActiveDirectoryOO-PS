[system.io.Fileinfo]$Module = Join-Path -Path $PSScriptRoot -ChildPath 'ad.psm1'
Import-Module -verbose -Name $Module

[system.io.Fileinfo]$ConfigPath = Join-Path -Path $PSScriptRoot -ChildPath 'test.psd1'
$config = Import-PowerShellDataFile -Path $ConfigPath 

$AD = New-ADConnection -Server $config.Server

$AD | Out-Host

Write-Host '------------------CREATING---------------------'
$User = $AD.CreateUser('DeleteMe')
 
$User.QuickEnable(8)

$User.SetEmployeeID(999999)
$User.SetDescription('this is a test account the will be deleted instantly')


$User | Out-Host

Write-Host '------------------DELETING---------------------'
$AD.DeleteUser($User)

$User | Out-Host

