#Requires -Module ActiveDirectory

function New-ADConnection {
    param(
        [string]$Server
    )
    return [ActiveDirectoryDomainController]::new($Server)
}

class ActiveDirectoryDomainController {
    [string]$HostName
    [string]$Domain
    [ipaddress]$IPv4Address
    [string]$OperatingSystem
    [pscredential]$Credential
    [string]$Username
    [string]$Password
    # new
    ActiveDirectoryDomainController([string]$Server) {
        $this.SetServer($Server)
    }
    ActiveDirectoryDomainController([string]$Server, [string]$Username, [string]$Password) {
        $this.SetServer($Server)
        $this.SetCredential($Username, $Password)
    }
    # Clone
    ActiveDirectoryDomainController([ActiveDirectoryDomainController]$Source) {
       $this.DeepPaste($Source)
    }
    ActiveDirectoryDomainController([string]$HostName,[string]$Domain,[ipaddress]$IPv4Address,[string]$OperatingSystem,[pscredential]$Credential,[string]$Username,[string]$Password){
        $this.HostName = $HostName
        $this.Domain = $Domain
        $this.IPv4Address = $IPv4Address
        $this.OperatingSystem = $OperatingSystem
        $this.Credential = $Credential
        $this.Username = $Username
        $this.Password = $Password
    }

    # returns a new ActiveDirectoryDomainController with properties that match its own. 
    [ActiveDirectoryDomainController] DeepCopy(){
        return [ActiveDirectoryDomainController]::New($this.HostName,$this.Domain,$this.IPv4Address,$this.OperatingSystem,$this.Credential,$this.Username,$this.Password)
    }
    # takes another ActiveDirectoryDomainController and copies each property into itself.
    DeepPaste([ActiveDirectoryDomainController]$Source){
        $this.HostName = $Source.HostName
        $this.Domain = $Source.Domain
        $this.IPv4Address = $Source.IPv4Address
        $this.OperatingSystem = $Source.OperatingSystem
        $this.Credential = $Source.Credential
        $this.Username = $Source.Username
        $this.Password = $Source.Password
    }
    SetServer([string]$Server) {
        $Source = Get-ADDomainController -Server $Server
        $this.HostName = $Source.HostName
        $this.Domain = $Source.Domain
        $this.IPv4Address = [ipaddress]::parse($Source.IPv4Address.ToString())
        $this.OperatingSystem = $Source.OperatingSystem
    }
    SetCredential([string]$User, [string]$Pass) {
        $this.Username = $User
        $this.Password = $Pass
        $SecureString = ConvertTo-SecureString $Pass -AsPlainText -Force
        $Cred = [System.Management.Automation.PSCredential]::new($User, $SecureString)
        $this.Credential = $Cred
    }
    [hashtable] ToCmdletSplat() {
        $splat = @{}
        $splat.Server = $this.HostName
        if ($this.Credential) {
            $splat.Credential = $this.Credential
        }
        return $splat
    }
    hidden [PSObject] GetADUserByFilter([string]$LDAPDisplayName, [string]$Value, [string[]]$Properties) {
        $AD = $this.ToCmdletSplat()
        return Get-ADUser @AD -Filter "$LDAPDisplayName -eq '$Value'" -Properties $Properties
    }
    hidden [PSObject] GetADUserByEmployeeID([string]$ID) {
        $AD = $this.ToCmdletSplat()
        return Get-ADUser @AD -Filter "EmployeeID -eq '$ID'" -Properties '*'
    }
    hidden [PSObject] GetADUserByEmployeeID([string]$ID,[string[]]$Properties) {
        $AD = $this.ToCmdletSplat()
        return Get-ADUser @AD -Filter "EmployeeID -eq '$ID'" -Properties $Properties
    }
    hidden [PSObject] GetADUserByIdentity([string]$ID) {
        $AD = $this.ToCmdletSplat()
        return Get-ADUser @AD -Identity $ID -Properties '*'
    }
    hidden [PSObject] GetADUserByIdentity([string]$ID,[string[]]$Properties) {
        $AD = $this.ToCmdletSplat()
        return Get-ADUser @AD -Identity $ID -Properties $Properties
    }
    # factory method for generating ActiveDirectoryUser from exeisting ADUsers
    [ActiveDirectoryUser] GetUserByEmployeeID([string]$ID) {
        $ADUser = $this.GetADUserByEmployeeID($ID)
        return [ActiveDirectoryUser]::new($ADUser, $this.DeepCopy())
    }
    # factory method for generating ActiveDirectoryUser from exeisting ADUsers
    [ActiveDirectoryUser] GetUserByIdentity([string]$ID) {
        $ADUser = $this.GetADUserByIdentity($ID)
        return [ActiveDirectoryUser]::new($ADUser, $this.DeepCopy())
    }
    [ActiveDirectoryUser] CreateUser([string]$Name) {
        $AD = $this.ToCmdletSplat()
        $CreateParams = @{
            Name        = $Name
            PassThru    = $true
            Confirm     = $false
            ErrorAction = 'stop'
        }
        try{
            $NewUser = New-ADUser @AD @CreateParams 
            $ADUser = $this.GetADUserByIdentity($NewUser.ObjectGuid)
            return [ActiveDirectoryUser]::new($ADUser, $this.DeepCopy())
        }
        catch{
            throw $psitem
        }
    }
    DeleteUser([ActiveDirectoryUser]$User){
        $AD = $this.ToCmdletSplat()
        $DeleteParams = @{
            Identity    = $User.ObjectGuid 
            Confirm     = $false
            ErrorAction = 'stop'
        }
        try{
            Remove-ADUser @AD @DeleteParams
            $User.Clear()
        }
        catch{
            throw $psitem
        }
    }
    DeleteUserIfExists([ActiveDirectoryUser]$User){
        try {
            $this.DeleteUser()
        }
        catch {
            if($psitem.CategoryInfo -like '*ADIdentityNotFoundException*'){
                return
            }
            throw $psitem
        }
    }
}



# this is a setable version of the ADUser object.
# enables a mcking of an aduser
# should not contain business logic
class ActiveDirectoryUser {
    # Identity
    [guid]$ObjectGuid
    [string]$SID
    [string]$DistinguishedName
    [string]$CanonicalName
    
    # Gettables
    [Nullable[Datetime]]$Created
    [Nullable[Datetime]]$PasswordLastSet
    [Nullable[bool]]$PasswordExpired
    [Nullable[bool]]$PasswordNeverExpires
    [Nullable[bool]]$PasswordNotRequired
    [string]$PrimaryGroup
    [Nullable[bool]]$LastLogonDate
    [Nullable[Datetime]]$AccountExpirationDate
    
    # Settables
    [string]$Name
    [string]$SamAccountName
    [string]$UserPrincipalName
    [string]$EmailAddress 
    [string]$EmployeeID 
    [string]$EmployeeNumber 
    [string]$AccountPassword 
    [Nullable[bool]]$Enabled 
    [string]$GivenName
    [string]$Surname
    [string]$DisplayName 
    [string]$Description 
    [string]$Title  
    [string]$Organization
    [string]$Company 
    [string]$Office 
    [string]$Department 
    [string]$Division 
    [string]$City 
    [string]$State
    [string]$Fax 
    [string]$MobilePhone 
    [string]$OfficePhone 
    [string]$PostalCode 
    [string]$POBox
    [System.Collections.ArrayList]$MemberOf

    hidden [ActiveDirectoryDomainController]$DC
    SetDomainController([ActiveDirectoryDomainController]$DC){
        $this.DC = $DC
    }

    # get an account
    ActiveDirectoryUser([PSObject]$Source, [ActiveDirectoryDomainController]$DC) {
        $this.ConvertFromADUser($Source)
        $This.SetDomainController($DC)
    }

    # Create an account
    ActiveDirectoryUser([string]$Name, [int]$EmployeeID, [ActiveDirectoryDomainController]$DC) {
        $This.SetDomainController($DC)
        $AD = $this.DC.ToCmdletSplat()
        $CreateParams = @{
            Name           = $Name
            #SamAccountName = $SamAccountName
            EmployeeID     = $EmployeeID
            PassThru       = $true
            Confirm        = $false
        }
        $NewUser = New-ADUser @AD @CreateParams
        $this.ConvertFromADUser($NewUser)
    }

    # control which objects get updated...
    # this is a sucky verbos process but its neccarcary to not over write certain properties.
    ConvertFromADUser([PSObject]$Source) {
        $this.ObjectGuid = $Source.ObjectGuid
        $this.SamAccountName = $Source.SamAccountName
        $this.DistinguishedName = $Source.DistinguishedName
        $this.UserPrincipalName = $Source.UserPrincipalName
        $this.Name = $Source.Name
        $this.SID = $Source.SID
        $this.EmailAddress = $Source.EmailAddress
        $this.EmployeeID = $Source.EmployeeID
        $this.EmployeeNumber = $Source.EmployeeNumber
        $this.Enabled = $Source.Enabled
        $this.GivenName = $Source.GivenName
        $this.Surname = $Source.Surname
        $this.DisplayName = $Source.DisplayName
        $this.Description = $Source.Description
        $this.Title = $Source.Title
        $this.Organization = $Source.Organization
        $this.Company = $Source.Company
        $this.Office = $Source.Office
        $this.Department = $Source.Department
        $this.Division = $Source.Division
        $this.City = $Source.City
        $this.State = $Source.State
        $this.Fax = $Source.Fax
        $this.MobilePhone = $Source.MobilePhone
        $this.OfficePhone = $Source.OfficePhone
        $this.PostalCode = $Source.PostalCode
        $this.POBox = $Source.POBox
        $this.MemberOf = $Source.MemberOf
        $this.Created = $Source.Created
        $this.PasswordLastSet = $Source.PasswordLastSet
        $this.PasswordExpired = $Source.PasswordExpired
        $this.PasswordNeverExpires = $Source.PasswordNeverExpires
        $this.PasswordNotRequired = $Source.PasswordNotRequired
        $this.PrimaryGroup = $Source.PrimaryGroup
        $this.CanonicalName = $Source.CanonicalName
        $this.LastLogonDate = $Source.LastLogonDate
        $this.AccountExpirationDate = $Source.AccountExpirationDate
    }
    hidden Refresh() {
        $u = $this.DC.GetADUserByIdentity($this.ObjectGuid)
        $this.ConvertFromADUser($u)
    }
    hidden Clear(){
        $members = $this | Get-Member  | Where-Object {$psitem.MemberType -like '*Prop*' -and $psitem.Definition -like '*set;*'}
        [array]$Properties = $members.Name
        foreach ( $Property in $Properties ) {
            if( $this."$Property" -is [Nullable[Datetime]]){
                $this."$Property" = $null
            }
            elseif($this."$Property" -is [guid]){
                $this."$Property" = [guid]::New("00000000-0000-0000-0000-000000000000")
            }
            else{
                $this."$Property" = $null
            }
        }
    }
    SetOU([string]$OrgUnit) {
        $AD = $this.DC.ToCmdletSplat()
        $ADOrgUnit = Get-ADOrganizationalUnit @AD -Identity $OrgUnit
        $ADUser = Move-ADObject @AD -Identity $this.ObjectGuid -TargetPath $ADOrgUnit.DistinguishedName -PassThru
        $this.DistinguishedName = $ADUser.DistinguishedName
    }
    AddGroupMemberships([string[]]$Groups) {
        $AD = $this.DC.ToCmdletSplat()
        foreach ($Group in $Groups) {
            $ADGroup = Get-ADGroup -Identity $Group
            Add-ADPrincipalGroupMembership @AD -Identity $this.ObjectGuid -MemberOf $ADGroup.ObjectGuid
            $this.MemberOf.Add($ADGroup.DistinguishedName)
        }
    }
    RemoveGroupMemberships([string[]]$Groups) {
        $AD = $this.DC.ToCmdletSplat()
        foreach ($Group in $Groups) {
            $ADGroup = Get-ADGroup -Identity $Group
            Add-ADPrincipalGroupMembership @AD -Identity $this.ObjectGuid -MemberOf $ADGroup.ObjectGuid -Confirm:$false
            $this.MemberOf.Remove($ADGroup.DistinguishedName)
        }
    }
    [psobject]GetGroupMemberships() {
        [System.Collections.ArrayList]$Groups = @()
        foreach ($Group in $this.MemberOf) {
            $ADGroup = Get-ADGroup -Identity $Group
            $Groups.add($ADGroup)
        }
        return $Groups
    }
    SetGroupMemberships([string[]]$Groups){
        $AD = $this.DC.ToCmdletSplat()
        # get memberships
        [System.Collections.ArrayList]$CurrentGroups = $this.GetGroupMemberships()
        [System.Collections.ArrayList]$NewGroups = @()
        foreach ($Group in $Groups) {
            $ADGroup = Get-ADGroup @AD -Identity $Group
            $NewGroups.Add($ADGroup)
        }
        # remove any CurrentGroup that is not in NewGroup
        foreach($CurrentGroup in $CurrentGroups){
            if($NewGroups.ObjectGuid -notcontains $CurrentGroup.ObjectGuid){
                $this.RemoveGroupMemberships($CurrentGroup.ObjectGuid)
            }
        }
        # add any NewGroup that in not in Current Group
        foreach($NewGroup in $NewGroups){
            if($CurrentGroups.ObjectGuid -notcontains $NewGroup.ObjectGuid){
                $this.AddGroupMemberships($NewGroup.ObjectGuid)
            }
        }
    }

    # QuickEnable makes enabling an account easier
    QuickEnable([string]$Password) {
        $this.SetAccountPassword($Password)
        $this.Unlock()
        $this.ClearExpiration()
        $this.Enable()
    }
    QuickEnable([int]$RandPassLen) {
        $this.SetAccountPasswordRandom($RandPassLen)
        $this.Unlock()
        $this.ClearExpiration()
        $this.Enable()
    }
    QuickEnable() {
        $this.Unlock()
        $this.ClearExpiration()
        $this.Enable()
    }

    Enable() {
        $AD = $this.DC.ToCmdletSplat()
        try{
            Enable-ADAccount @AD -Identity $this.ObjectGuid -Confirm:$false -ErrorAction 'stop'
            $this.Enabled = $true
        }
        catch{
            $err = @{
                Error = $PSItem
                HelpMessage = 'Failed to enable the Account. Please make sure the account has a valid password set before trying to enable it. Also check that the account does not have an expiration date set. You could try using the QuickEnable() method wich takes care of some of these details for you.'
            }
            throw $err
        }
    }
    Disable() {
        $AD = $this.DC.ToCmdletSplat()
        Disable-ADAccount @AD -Identity $this.ObjectGuid -Confirm:$false
    }
    Unlock() {
        $AD = $this.DC.ToCmdletSplat()
        Unlock-ADAccount @AD -Identity $this.ObjectGuid -Confirm:$false
    }
    SetExpiration([datetime]$DT) {
        $AD = $this.DC.ToCmdletSplat()
        Set-ADAccountExpiration @AD -Identity $this.ObjectGuid  -DateTime $DT -Confirm:$false
    }
    ClearExpiration() {
        $AD = $this.DC.ToCmdletSplat()
        Clear-ADAccountExpiration @AD -Identity $this.ObjectGuid -Confirm:$false
    }

    # only use $properties directiry support by the Set-ADUser startdard ParameterSet
    hidden UpdateStandardProperty([string]$Property, [string]$Value) {
        $Param = @{}
        $Param += $this.DC.ToCmdletSplat()
        $Param.Identity = $this.ObjectGuid
        $Param.Add($Property, $Value)
        Set-ADUser @Param
        $this."$Property" = $Value
    }

    hidden ResetPassword([string]$Value){
        $AD = $this.DC.ToCmdletSplat()
        $SecureString = ConvertTo-SecureString $Value -AsPlainText -Force
        Set-ADAccountPassword @AD -Identity $this.ObjectGuid -NewPassword $SecureString -Reset -Confirm:$false -ErrorAction 'stop'
        $this.AccountPassword = $Value

        # refresh similar properties
        $ADUser = $this.DC.GetADUserByIdentity($this.ObjectGuid,@('PasswordLastSet','PasswordExpired','PasswordNeverExpires','PasswordNotRequired'))
        $this.PasswordExpired = $ADUser.PasswordExpired
        $this.PasswordLastSet = $ADUser.PasswordLastSet
        $this.PasswordNeverExpires = $ADUser.PasswordNeverExpires
        $this.PasswordNotRequired = $ADUser.PasswordNotRequired
    }

    # generic random passwords compliant with stardard AD requirements
    hidden [string] GenerateRandomPassword([int]$Length,[int]$Complexity){
        if($Length -lt 5){
            Throw "Random pasword length must be greater then 4 characters"
        }
        if($Length -gt 128){
            Throw "Max random pasword length is 128 characters"
        }
        if($Complexity -gt $Length){
            Throw "Random password complexity must be less than the pasword length"
        }
        # Standard AD Requirements
	    $COUNT = [regex]::new(".{$Length}")
	    $SPECIAL = [regex]::new('[!@#$%<>^&?]')
	    $LOWER = [regex]::new('[a-z]')
	    $UPPER = [regex]::new('[A-Z]')
	    $NUMBER = [regex]::new('[0-9]')
	    DO {
	    	try{
	    		$Password = [System.Web.Security.Membership]::GeneratePassword( $Length, $Complexity)
	    	}
	    	catch{
	    		throw $psitem
	    	}
	    	$Meets_Complexity = $true
	    	if (!$COUNT.Match($Password).Success) {$Meets_Complexity = $false}
	    	if (!$SPECIAL.Match($Password).Success) {$Meets_Complexity = $false}
	    	if (!$LOWER.Match($Password).Success) {$Meets_Complexity = $false}
	    	if (!$UPPER.Match($Password).Success) {$Meets_Complexity = $false}
	    	if (!$NUMBER.Match($Password).Success) {$Meets_Complexity = $false}
	    }
	    Until($Meets_Complexity)
	    return $Password
    }
    # Setters for User Properties
    # these should also update active directory at the same time
    SetSamAccountName([string]$Value) {
        $this.UpdateStandardProperty('SamAccountName', $Value)
    }
    SetUserPrincipalName([string]$Value) {
        $this.UpdateStandardProperty('UserPrincipalName', $Value)
    }
    SetEmailAddress ([string]$Value) {
        $this.UpdateStandardProperty('EmailAddress', $Value)
    }
    SetEmployeeID([string]$Value) {
        $this.UpdateStandardProperty('EmployeeID', $Value)
    }
    SetEmployeeNumber([string]$Value) {
        $this.UpdateStandardProperty('EmployeeNumber', $Value)
    }
    SetAccountPassword([string]$Value) {
        $this.ResetPassword($Value)
    }
    SetAccountPasswordRandom([string]$Length) {
        $Complexity = [math]::floor($Length/2)
        $NewPassword = $this.GenerateRandomPassword($Length,$Complexity)
        try{
            $this.ResetPassword($NewPassword)
        }
        catch{
            $Err = @{
                Error = $PSItem
                Help  = "Please make sure the password length meets your Active Directory password policy. The random password generator provided by this module ensures the random password is the length you specify and all of the following type exists in the random password: lowercase letter, uppercase Letter, special character, number. If your domain has a very rigid password policy you should consider generating the random password yourself and then use the SetAccountPassword() Method instead."
            }
            throw 
        }
    }
    SetGivenName([string]$Value) {
        $this.UpdateStandardProperty('GivenName', $Value)
    }
    SetSurname([string]$Value) {
        $this.UpdateStandardProperty('Surname', $Value)
    }
    SetDisplayName([string]$Value) {
        $this.UpdateStandardProperty('DisplayName', $Value)
    }
    SetDescription([string]$Value) {
        $this.UpdateStandardProperty('Description', $Value)
    }
    SetTitle([string]$Value) {
        $this.UpdateStandardProperty('Description', $Value)
    }
    SetOrganization([string]$Value) {
        $this.UpdateStandardProperty('Organization', $Value)
    }
    SetCompany([string]$Value) {
        $this.UpdateStandardProperty('Company', $Value)
    }
    SetOffice([string]$Value) {
        $this.UpdateStandardProperty('Office', $Value)
    }
    SetDepartment([string]$Value) {
        $this.UpdateStandardProperty('Department', $Value)
    }
    SetDivision([string]$Value) {
        $this.UpdateStandardProperty('Division', $Value)
    }
    SetCity([string]$Value) {
        $this.UpdateStandardProperty('City', $Value)
    }
    SetState([string]$Value) {
        $this.UpdateStandardProperty('State', $Value)
    }
    SetFax([string]$Value) {
        $this.UpdateStandardProperty('Fax', $Value)
    }
    SetMobilePhone([string]$Value) {
        $this.UpdateStandardProperty('MobilePhone', $Value)
    }
    SetOfficePhone([string]$Value) {
        $this.UpdateStandardProperty('OfficePhone', $Value)
    }
    SetPostalCode([string]$Value) {
        $this.UpdateStandardProperty('PostalCode', $Value)
    }
    SetPOBox([string]$Value) {
        $this.UpdateStandardProperty('POBox', $Value)
    }
}
