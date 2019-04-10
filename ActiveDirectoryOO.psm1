function New-Credential {
    param(
        [parameter(Mandatory = $true)]
        [alias("u")]
        [string]
        $Username,

        [parameter(Mandatory = $true)]
        [alias("p")]
        [string]
        $Password
    )
    $SecureString = ConvertTo-SecureString $Password -AsPlainText -Force
    return [System.Management.Automation.PSCredential]::new($Username, $SecureString)
}
function ConvertTo-Hashtable {
    param (
        [parameter(ValueFromPipeline, Mandatory)]
        [psobject]$InputObject,
        [string[]]$Include,
        [string[]]$Exclude
    )
    [hashtable]$OutputObject = @{}
    # Datarow
    if ($InputObject -is [System.Data.Datarow]) {
        foreach ($Column in $InputObject.Table.Columns) {
            $Value = $InputObject[$Column]
            $Key = $Column.ColumnName
            if ($Include -and $Include[0] -ne '*' -and $Include -NotContains $Key) {
                continue
            }
            if ($Exclude -and $Exclude -Contains $Key) {
                continue
            }
            $OutputObject.Add($Key, $Value)
        }
        return $OutputObject
    }
    # Hashtable
    # creates a new hashtable with filtered keys,values
    elseif ($InputObject -is [Hashtable]) {
        foreach ($Key in $InputObject.Keys) {
            $Value = $InputObject[$Key]
            if ($Include -and $Include[0] -ne '*' -and $Include -NotContains $Key) {
                continue
            }
            if ($Exclude -and $Exclude -Contains $Key) {
                continue
            }
            $OutputObject.Add($Key, $Value)
        }
        return $OutputObject
    }
    
    # Anonymous objects
    else {
        $Members = $InputObject | Get-Member 
        $Properties = $Members | where-object -FilterScript {
            $psitem.MemberType -like '*Prop*' -and 
            $psitem.MemberType -notlike '*Script*' 
        }
        $Keys = $Properties.Name
        foreach ($Key in $Keys) {
            
            # Filters
            if ($Include -and $Include[0] -ne '*' -and $Include -NotContains $Key) {
                continue
            }
            if ($Exclude -and $Exclude -Contains $Key) {
                continue
            }

            $Value = $InputObject."$Key"
            $OutputObject.Add($Key, $Value)
        }
        return $OutputObject
    }
}






















function New-ADDCConnection {
    param(
        [string]$Server,
        [string]$Username,
        [string]$Password
    )
    if ($Username -and $Password) {
        return [ADDCConnection]::New($Server, $Username, $Password)
    }
    else {
        return [ADDCConnection]::New($Server)
    }
}

class ADDCConnection {
    [string]$Server
    [pscredential]$Credential

    ADDCConnection([string]$Server) {
        $this.Server = $Server
    }
    ADDCConnection([string]$Server, [pscredential]$Credential) {
        $this.Server = $Server
        $this.Credential = $Credential
    }
    ADDCConnection([string]$Server, [string]$Username, [string]$Password) {
        $this.Server = $Server
        $this.SetCredential($Username, $Password)
    }

    [hashtable]AuthSplat() {
        $Auth = @{
            Server = $this.Server
        }
        if ($this.Credential) {
            $Auth.Add('Credential', $this.Credential)
        }
        return $Auth
    }
    SetCredential([string]$User, [string]$Pass) {
        $Secure = ConvertTo-SecureString $Pass -AsPlainText -Force
        $this.Credential = [PSCredential]::new($User, $Secure)
    }
    [hashtable] OrganizationalUnit([string]$Identity,[string[]]$Properties){
        $Auth = $this.AuthSplat()
        $ou = Get-ADRrganizationalUnit @Auth -Identity $Identity -Properties $Properties
        return ConvertTo-Hashtable $ou -Include $Properties
    }
    [hashtable] Group([string]$Identity,[string[]]$Properties){
        $Auth = $this.AuthSplat()
        $Group = Get-ADGroup @Auth -Identity $Identity -Properties $Properties
        return ConvertTo-Hashtable $Group 
    }
    [hashtable] Group([guid]$ObjectGuid,[string[]]$Properties){
        $Auth = $this.AuthSplat()
        $Group = Get-ADGroup @Auth -Identity $ObjectGuid -Properties $Properties
        return ConvertTo-Hashtable $Group -Include $Properties
    }

    [ADUserConnection] NewADUserConnection ( [String]$Identity ) {
        $Auth = $this.AuthSplat()
        $User = Get-Aduser @Auth -Identity $Identity
        if (!$User) {return $null}
        return [ADUserConnection]::new($this, $User.ObjectGuid)
    }
    [ADUserConnection[]] NewADUserConnections ([string]$Filter) {
        $Auth = $this.AuthSplat()
        [array]$Users = Get-Aduser @Auth -Filter $Filter
        if (!$Users) {return $null}
        $Connections = [System.Array]::CreateInstance([ADUserConnection], $Users.Count)
        foreach ($ObjectGuid in $Users.ObjectGuid) {
            $Connections += [ADUserConnection]::new($this, $ObjectGuid)
        }
        return $Connections
    }
}

























function New-ADUserConnections {
    param (
        [Parameter(Mandatory)]
        [string]$Server,

        [Parameter(Mandatory)]
        [string]$Filter,

        [pscredential]$Credential
    )
    return [ADDCConnection]::new($Server,$Credential).NewADUserConnections($Filter)
}


function New-ADUserConnection {
    param (
        [Parameter(Mandatory)]
        [string]$Server,

        [Parameter(Mandatory)]
        [string]$Identity,

        [pscredential]$Credential
    )
    return [ADDCConnection]::new($Server,$Credential).NewADUserConnection($Identity)
}


<#
    represents an existing ADUser in Active Ditectory
    used to getting and setting properties on a user
#>
class ADUserConnection {
    hidden [guid]$ID
    [ADDCConnection]$DC
    [bool]$AllowUnsafeSets = $true

    ADUserConnection([ADDCConnection]$DC, $ObjectGuid) {
        $this.DC = $DC
        $this.ID = $ObjectGuid
    }
    [string] ToString(){
        return $this.ID.ToString()
    }
    
    [hashtable] Get([string[]]$Properties) {
        $Auth = $this.DC.AuthSplat()
        $User = Get-Aduser @Auth -Identity $this.ObjectGuid() -Properties $Properties
        return ConvertTo-Hashtable $User -Include $Properties
    }
    [psobject] Get([string]$Property) {
        [string[]]$Properties = @($Property)
        [hashtable]$results = $this.Get($Properties)
        return $results[$Property]
    }
    # this will allow internal setters to skip the unsafe checking
    set([ADUserProperty]$Property, [psobject]$Value) {
        $CMD = @{$Property = $Value}
        $Auth = $this.DC.AuthSplat()
        Set-Aduser @Auth -Identity $this.ObjectGuid() @CMD 
    }

    Set([string]$Property, [psobject]$Value) {
        $this.set(@{$Property = $Value})
    }
    Set([hashtable]$Properties) {
        $SafeSets = @{}
        $HasSafeSets = $false
        $SafeSettableProperties = $this.SafeSettableProperties()
        foreach ($Key in $Properties.Keys) {
            $Value = $Properties[$Key]
            
            # Method Properties
            if ($Key -eq 'AccountPassword') {
                $this.AccountPassword($Value)
            }
            elseif ($Key -eq 'OrganizationalUnit') {
                $this.OrganizationalUnit($Value)
            }
            elseif ($Key -eq 'Groups') {
                $this.Groups($Value)
            }
        
            # is safe property
            elseif ($SafeSettableProperties -contains $Key) {
                    $SafeSets.Add($Key, $Value)
                    $HasSafeSets = $true
            }

            # perform unsafe sets one at a time.
            elseif ($this.AllowUnsafeSets) {
                $this.UnsafeSet($Key, $Value)
            }
        }
        # perform safe sets all at once
        if ($HasSafeSets) {
            $Auth = $this.DC.AuthSplat()
            Set-Aduser @Auth -Identity $this.ObjectGuid() @SafeSets 
        }
    }
    hidden [string[]] SafeSettableProperties([string]$Property) {
        return [ADUserProperty].GetFields().Name | Where-Object {$psitem -ne 'value__'} 
    }


    # set non-standard property. 
    # this is unsafe becuase we know nothing about the property.
    hidden UnsafeSet([string]$Property, $Value) {
        $CMD = @{}

        # Null
        elseif ($Value -is [dbnull] -or $null -eq $Value) {
            $CMD = @{Clear = @($Property)}
        }
        # default
        else {
            $CMD = @{Replace = @{$Property = $Value}}
        }

        $Auth = $this.DC.AuthSplat()
        Set-Aduser @Auth -Identity $this.ObjectGuid() @CMD 
    }

    
    
    
    
    ##################################### Property Getters #####################################
    ############################################################################################
    
    [guid] ObjectGuid () {return $this.ID}
    [string[]] MemberOf () { return $this.Get('MemberOf')}

    # better version of MemberOf()
    [hashtable[]] Groups(){
        $CurrentMemberOf = $this.MemberOf()
        [hashtable[]]$CurrentGroups = @()
        foreach($Group in $CurrentMemberOf){
            [hashtable[]]$CurrentGroups += $this.DC.Group($Group,@('ObjectGuid','SamAccountName','DistinguishedName','Created','ObjectClass'))
        }
        return $CurrentGroups
    }

    [hashtable] OrganizationalUnit(){
        $dn = $this.DistinguishedName() -split ','
        $li = $dn.Count -1
        $ou = $dn[1..$li] -join ','
        return $this.DC.OrganizationalUnit($ou,@('ObjectGuid','DistinguishedName','Created','ObjectClass'))
    }


    [nullable[DateTime]] AccountExpirationDate () { return $this.Get('AccountExpirationDate')}
    [Boolean] AccountNotDelegated () { return $this.Get('AccountNotDelegated')}
    [Boolean] AllowReversiblePasswordEncryption () { return $this.Get('AllowReversiblePasswordEncryption')}
    [psobject] AuthenticationPolicy () { return $this.Get('AuthenticationPolicy')}
    [psobject] AuthenticationPolicySilo () { return $this.Get('AuthenticationPolicySilo')}
    [Boolean] CannotChangePassword () { return $this.Get('CannotChangePassword')}
    [Hashtable] Certificates () { return $this.Get('Certificates')}
    [Boolean] ChangePasswordAtLogon () { return $this.Get('ChangePasswordAtLogon')}
    [string] City () { return $this.Get('City')}
    [string] Company () { return $this.Get('Company')}
    [bool] CompoundIdentitySupported () { return $this.Get('CompoundIdentitySupported')}
    [string] Country () { return $this.Get('Country')}
    [string] Department () { return $this.Get('Department')}
    [string] Description () { return $this.Get('Description')}
    [string] DisplayName () { return $this.Get('DisplayName')}
    [string] Division () { return $this.Get('Division')}
    [string] EmailAddress () { return $this.Get('EmailAddress')}
    [string] EmployeeID () { return $this.Get('EmployeeID')}
    [string] EmployeeNumber () { return $this.Get('EmployeeNumber')}
    [bool] Enabled () { return $this.Get('Enabled')}
    [string] Fax () { return $this.Get('Fax')}
    [string] GivenName () { return $this.Get('GivenName')}
    [string] HomeDirectory () { return $this.Get('HomeDirectory')}
    [string] HomeDrive () { return $this.Get('HomeDrive')}
    [string] HomePage () { return $this.Get('HomePage')}
    [string] HomePhone () { return $this.Get('HomePhone')}
    [string] Initials () { return $this.Get('Initials')}
    [psobject] KerberosEncryptionType () { return $this.Get('KerberosEncryptionType')}
    [string] LogonWorkstations () { return $this.Get('LogonWorkstations')}
    [psobject] Manager () { return $this.Get('Manager')}
    [string] MobilePhone () { return $this.Get('MobilePhone')}
    [string] Office () { return $this.Get('Office')}
    [string] OfficePhone () { return $this.Get('OfficePhone')}
    [string] Organization () { return $this.Get('Organization')}
    [string] OtherName () { return $this.Get('OtherName')}
    [string] Partition () { return $this.Get('Partition')}
    [bool] PasswordNeverExpires () { return $this.Get('PasswordNeverExpires')}
    [bool] PasswordNotRequired () { return $this.Get('PasswordNotRequired')}
    [string] POBox () { return $this.Get('POBox')}
    [string] PostalCode () { return $this.Get('PostalCode')}
    [psobject] PrincipalsAllowedToDelegateToAccount () { return $this.Get('PrincipalsAllowedToDelegateToAccount')}
    [string] ProfilePath () { return $this.Get('ProfilePath')}
    [string] SamAccountName () { return $this.Get('SamAccountName')}
    [string] ScriptPath () { return $this.Get('ScriptPath')}
    [hashtable] ServicePrincipalNames () { return $this.Get('ServicePrincipalNames')}
    [bool] SmartcardLogonRequired () { return $this.Get('SmartcardLogonRequired')}
    [string] State () { return $this.Get('State')}
    [string] StreetAddress () { return $this.Get('StreetAddress')}
    [string] Surname () { return $this.Get('Surname')}
    [string] Title () { return $this.Get('Title')}
    [bool] TrustedForDelegation () { return $this.Get('TrustedForDelegation')}
    [string] UserPrincipalName () { return $this.Get('UserPrincipalName')}
    
    [Int64] accountExpires() {
        return $this.Get('accountExpires')
    }
    
    [nullable[datetime]]AccountLockoutTime() {return $this.Get('AccountLockoutTime')}
    [int] BadLogonCount() {return $this.Get('BadLogonCount')}
    [Int64] badPasswordTime() {return $this.Get('badPasswordTime')}
    [Int32] badPwdCount() {return $this.Get('badPwdCount')}
    [string] CanonicalName() {return $this.Get('CanonicalName')}
    [string] CN() {return $this.Get('CN')}
    [Int64] codePage() {return $this.Get('codePage')}
    [Int32] countryCode() {return $this.Get('countryCode')}
    [datetime] Created() {return $this.Get('Created')}
    [datetime] createTimeStamp() {return $this.Get('createTimeStamp')}
    [psobject] Deleted() {return $this.Get('Deleted')} #???
    [string] DistinguishedName() {return $this.Get('DistinguishedName')}
    [bool] DoesNotRequirePreAuth() {return $this.Get('DoesNotRequirePreAuth')}
    [bool] HomedirRequired() {return $this.Get('HomedirRequired')}
    [Int32] instanceType() {return $this.Get('instanceType')}
    [psobject] isDeleted() {return $this.Get('isDeleted')} #???
    [Nullable[datetime]] LastBadPasswordAttempt() {return $this.Get('LastBadPasswordAttempt')}
    [psobject] LastKnownParent() {return $this.Get('LastKnownParent')} #???
    [Int64] lastLogoff() {return $this.Get('lastLogoff')}
    [Int64] lastLogon() {return $this.Get('lastLogon')} 
    [Nullable[datetime]] LastLogonDate() {return $this.Get('LastLogonDate')} 
    [bool] LockedOut() {return $this.Get('LockedOut')} 
    [Int32] logonCount() {return $this.Get('logonCount')} 
    [datetime] Modified() {return $this.Get('Modified')} 
    [datetime] modifyTimeStamp() {return $this.Get('modifyTimeStamp')} 
    [string] Name() {return $this.Get('Name')} 
    [string] ObjectCategory() {return $this.Get('ObjectCategory')} 
    [string] ObjectClass() {return $this.Get('ObjectClass')} 
    [System.Security.Principal.SecurityIdentifier] objectSid() {return $this.Get('objectSid')} 
    [bool] PasswordExpired() {return $this.Get('PasswordExpired')} 
    [Nullable[datetime]] PasswordLastSet() {return $this.Get('PasswordLastSet')} 
    [string] PrimaryGroup() {return $this.Get('PrimaryGroup')} 
    [Int32] primaryGroupID() {return $this.Get('primaryGroupID')} 
    [bool] ProtectedFromAccidentalDeletion() {return $this.Get('ProtectedFromAccidentalDeletion')} 
    [Int64] pwdLastSet() {return $this.Get('pwdLastSet')}
    [Int32] sAMAccountType() {return $this.Get('sAMAccountType')}
    [System.Security.Principal.SecurityIdentifier] SID() {return $this.Get('SID')}
    [psobject] SIDHistory() {return $this.Get('SIDHistory')} #???
    [bool] TrustedToAuthForDelegation() {return $this.Get('TrustedToAuthForDelegation')}
    [Int32] userAccountControl() {return $this.Get('userAccountControl')}
    [psobject] userCertificate() {return $this.Get('userCertificate')}



    ##################################### Property Setters #####################################
    ############################################################################################
    AccountPassword([securestring]$Password) {
        $Auth = $this.DC.AuthSplat()
        Set-ADAccountPassword @Auth -Identity $this.ObjectGuid() -Reset -Confirm:$False -NewPassword $Password
    }
    AccountPassword([string]$Password) {
        $SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
        $this.AccountPassword($SecurePassword)
    }
    Groups([String[]]$NewGroups){
        [guid[]]$NewGroupGuids = @()
        $Auth = $this.DC.AuthSplat()
        foreach($Group in $NewGroups){
            $Group = Get-ADGroup @Auth -Identity $this.ObjectGuid()
            [guid[]]$NewGroupGuids += $Group.ObjectGuid
        }
        $this.MemberOf($NewGroupGuids)
    }
    Groups([guid[]]$NewGroupGuids) {
        $CurrentMemberOf = $this.MemberOfGuids()
        [system.collections.Arraylist]$AddMemberOfs = @()
        [system.collections.Arraylist]$RemoveMemberOfs = @()
        
        # find memberOf to add
        foreach($Group in $NewGroupGuids){
            if($CurrentMemberOf -notcontains $Group){
                $AddMemberOfs.Add($Group)
            }
        }
        if($AddMemberOfs){
            $this.JoinGroups($AddMemberOfs)
        }
        
        # find memberOf to remove
        foreach($Group in $CurrentMemberOf){
            if($NewGroupGuids -notcontains $Group){
            }
        }
        if($RemoveMemberOfs){
            $this.LeaveGroups($RemoveMemberOfs)
        }
    }
    JoinGroups([guid[]]$Groups){
        $Auth = $this.DC.AuthSplat()
        Add-ADPrincipalGroupMembership @Auth -Identity $this.ObjectGuid() -MemberOf $Groups -Confirm:$false
    }
    LeaveGroups([guid[]]$Groups){
        $Auth = $this.DC.AuthSplat()
        Remove-ADPrincipalGroupMembership @Auth -Identity $this.ObjectGuid -MemberOf $Groups -Confirm:$false
    }

    OrganizationalUnit([string]$Identity){
        $Auth = $this.DC.AuthSplat()
        $DN = $this.dc.OrganizationalUnit($Identity).DistinguishedName
        Move-ADObject @Auth -Identity $this.ObjectGuid() -TargetPath $DN -Confirm:$False
    }

    # AccountExpirationDate can be set by explicitly passing a datetime
    # AccountExpirationDate can be cleared implicity by passing a null
    AccountExpirationDate ([nullable[DateTime]]$Value) { 
        if ($null -eq $Value) {
            $this.ClearADAccountExpiration()
        }
        $this.Set([ADUserProperty]::AccountExpirationDate , $Value) 
    }

    # AccountExpirationDate can be cleared explicitly by passing a false boolean
    # AccountExpirationDate can be set implicity by passing a true boolean
    AccountExpirationDate ([bool]$Expiration) {
        if (!$Expiration) {
            $this.ClearADAccountExpiration()
        }
        else {
            $dt = Get-Date
            $this.AccountExpirationDate($dt)
        }
    }
    ClearADAccountExpiration(){
        $Auth = $this.DC.AuthSplat()
        Clear-ADAccountExpiration @Auth -Identity $this.ObjectGuid() -Confirm:$False
    }
    

    AccountNotDelegated ([Boolean]$Value) { $this.Set([ADUserProperty]::AccountNotDelegated , $Value) }
    AllowReversiblePasswordEncryption ([Boolean]$Value) { $this.Set([ADUserProperty]::AllowReversiblePasswordEncryption , $Value) }
    AuthenticationPolicy ([psobject]$Value) { $this.Set([ADUserProperty]::AuthenticationPolicy , $Value) }
    AuthenticationPolicySilo ([psobject]$Value) { $this.Set([ADUserProperty]::AuthenticationPolicySilo , $Value) }
    CannotChangePassword ([Boolean]$Value) { $this.Set([ADUserProperty]::CannotChangePassword , $Value) }
    Certificates ([Hashtable]$Value) { $this.Set([ADUserProperty]::Certificates , $Value) }
    ChangePasswordAtLogon ([Boolean]$Value) { $this.Set([ADUserProperty]::ChangePasswordAtLogon , $Value) }
    City ([String]$Value) { $this.Set([ADUserProperty]::City , $Value) }
    Company ([String]$Value) { $this.Set([ADUserProperty]::Company , $Value) }
    CompoundIdentitySupported ([Boolean]$Value) { $this.Set([ADUserProperty]::CompoundIdentitySupported , $Value) }
    Country ([String]$Value) { $this.Set([ADUserProperty]::Country , $Value) }
    Department ([String]$Value) { $this.Set([ADUserProperty]::Department , $Value) }
    Description ([String]$Value) { $this.Set([ADUserProperty]::Description , $Value) }
    DisplayName ([String]$Value) { $this.Set([ADUserProperty]::DisplayName , $Value) }
    Division ([String]$Value) { $this.Set([ADUserProperty]::Division , $Value) }
    EmailAddress ([String]$Value) { $this.Set([ADUserProperty]::EmailAddress , $Value) }
    EmployeeID ([String]$Value) { $this.Set([ADUserProperty]::EmployeeID , $Value) }
    EmployeeNumber ([String]$Value) { $this.Set([ADUserProperty]::EmployeeNumber , $Value) }
    Enabled ([Boolean]$Value) { $this.Set([ADUserProperty]::Enabled , $Value) }
    Fax ([String]$Value) { $this.Set([ADUserProperty]::Fax , $Value) }
    GivenName ([String]$Value) { $this.Set([ADUserProperty]::GivenName , $Value) }
    HomeDirectory ([String]$Value) { $this.Set([ADUserProperty]::HomeDirectory , $Value) }
    HomeDrive ([String]$Value) { $this.Set([ADUserProperty]::HomeDrive , $Value) }
    HomePage ([String]$Value) { $this.Set([ADUserProperty]::HomePage , $Value) }
    HomePhone ([String]$Value) { $this.Set([ADUserProperty]::HomePhone , $Value) }
    Initials ([String]$Value) { $this.Set([ADUserProperty]::Initials , $Value) }
    KerberosEncryptionType ([psobject]$Value) { $this.Set([ADUserProperty]::KerberosEncryptionType , $Value) }
    LogonWorkstations ([String]$Value) { $this.Set([ADUserProperty]::LogonWorkstations , $Value) }
    Manager ([psobject]$Value) { $this.Set([ADUserProperty]::Manager , $Value) }
    MobilePhone ([String]$Value) { $this.Set([ADUserProperty]::MobilePhone , $Value) }
    Office ([String]$Value) { $this.Set([ADUserProperty]::Office , $Value) }
    OfficePhone ([String]$Value) { $this.Set([ADUserProperty]::OfficePhone , $Value) }
    Organization ([String]$Value) { $this.Set([ADUserProperty]::Organization , $Value) }
    OtherName ([String]$Value) { $this.Set([ADUserProperty]::OtherName , $Value) }
    Partition ([String]$Value) { $this.Set([ADUserProperty]::Partition , $Value) }
    PasswordNeverExpires ([Boolean]$Value) { $this.Set([ADUserProperty]::PasswordNeverExpires , $Value) }
    PasswordNotRequired ([Boolean]$Value) { $this.Set([ADUserProperty]::PasswordNotRequired , $Value) }
    POBox ([String]$Value) { $this.Set([ADUserProperty]::POBox , $Value) }
    PostalCode ([String]$Value) { $this.Set([ADUserProperty]::PostalCode , $Value) }
    PrincipalsAllowedToDelegateToAccount ([psobject]$Value) { $this.Set([ADUserProperty]::PrincipalsAllowedToDelegateToAccount , $Value) }
    ProfilePath ([String]$Value) { $this.Set([ADUserProperty]::ProfilePath , $Value) }
    SamAccountName ([String]$Value) { $this.Set([ADUserProperty]::SamAccountName , $Value) }
    ScriptPath ([String]$Value) { $this.Set([ADUserProperty]::ScriptPath , $Value) }
    ServicePrincipalNames ([hashtable]$Value) { $this.Set([ADUserProperty]::ServicePrincipalNames , $Value) }
    SmartcardLogonRequired ([bool]$Value) { $this.Set([ADUserProperty]::SmartcardLogonRequired , $Value) }
    State ([String]$Value) { $this.Set([ADUserProperty]::State , $Value) }
    StreetAddress ([String]$Value) { $this.Set([ADUserProperty]::StreetAddress , $Value) }
    Surname ([String]$Value) { $this.Set([ADUserProperty]::Surname , $Value) }
    Title ([String]$Value) { $this.Set([ADUserProperty]::Title , $Value) }
    TrustedForDelegation ([bool]$Value) { $this.Set([ADUserProperty]::TrustedForDelegation , $Value) }
    UserPrincipalName ([String]$Value) { $this.Set([ADUserProperty]::UserPrincipalName , $Value) }
}


enum ADUserProperty {
    AccountExpirationDate
    AccountNotDelegated
    AllowReversiblePasswordEncryption
    AuthenticationPolicy
    AuthenticationPolicySilo
    CannotChangePassword
    Certificates
    ChangePasswordAtLogon
    City
    Company
    CompoundIdentitySupported
    Country
    Department
    Description
    DisplayName
    Division
    EmailAddress
    EmployeeID
    EmployeeNumber
    Enabled
    Fax
    GivenName
    HomeDirectory
    HomeDrive
    HomePage
    HomePhone
    Initials
    KerberosEncryptionType
    LogonWorkstations
    Manager
    MobilePhone
    Office
    OfficePhone
    Organization
    OtherName
    Partition
    PasswordNeverExpires
    PasswordNotRequired
    POBox
    PostalCode
    PrincipalsAllowedToDelegateToAccount
    ProfilePath
    SamAccountName
    ScriptPath
    ServicePrincipalNames
    SmartcardLogonRequired
    State
    StreetAddress
    Surname
    Title
    TrustedForDelegation
    UserPrincipalName
}


