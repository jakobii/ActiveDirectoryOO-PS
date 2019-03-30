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
    SetADUserProperties([guid]$ObjectGuid, [hashtable]$Properties) {
        $Auth = $this.AuthSplat()
        Set-Aduser @Auth -Identity $ObjectGuid @Properties 
    }
    [hashtable] GetADUserProperties([guid]$ObjectGuid, [string[]]$Properties) {
        $Auth = $this.AuthSplat()
        $User = Get-Aduser @Auth -Identity $ObjectGuid -Properties $Properties
        return ConvertTo-Hashtable $User -Include $Properties
    }
    SetADUserPassword([guid]$ObjectGuid, [securestring]$Password) {
        $Auth = $this.AuthSplat()
        Set-ADAccountPassword @Auth -Identity $ObjectGuid -Reset -Confirm:$False -NewPassword $Password
    }
    ClearADAccountExpiration([guid]$ObjectGuid) {
        $Auth = $this.AuthSplat()
        Clear-ADAccountExpiration @Auth -Identity $ObjectGuid -Confirm:$False
    }
    AddADPrincipalGroupMembership([guid]$ObjectGuid, [guid[]]$Groups) {
        $Auth = $this.AuthSplat()
        Add-ADPrincipalGroupMembership @Auth -Identity $ObjectGuid -MemberOf $Groups -Confirm:$false
    }
    RemoveADPrincipalGroupMembership([guid]$ObjectGuid, [guid[]]$Groups) {
        $Auth = $this.AuthSplat()
        Remove-ADPrincipalGroupMembership @Auth -Identity $ObjectGuid -MemberOf $Groups -Confirm:$false
    }
    [hashtable] GetADGroupByIdentity([string]$Identity,[string[]]$Properties){
        $Auth = $this.AuthSplat()
        $Group = Get-ADGroup @Auth -Identity $Identity -Properties $Properties
        return ConvertTo-Hashtable $Group 
    }
    [hashtable] GetADGroupProperties([guid]$ObjectGuid,[string[]]$Properties){
        $Auth = $this.AuthSplat()
        $Group = Get-ADGroup @Auth -Identity $ObjectGuid -Properties $Properties
        return ConvertTo-Hashtable $Group -Include $Properties
    }

    [ADUserConnection] NewADUserConnectionByIdentity ( [String]$Identity ) {
        $Auth = $this.AuthSplat()
        $User = Get-Aduser @Auth -Identity $Identity
        if (!$User) {return $null}
        return [ADUserConnection]::new($this, $User.ObjectGuid)
    }
    [ADUserConnection[]] NewADUserConnectionsByFilter ([string]$Filter) {
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

























function New-ADUserConnectionsByFilter {
    param (
        [Parameter(Mandatory)]
        [string]$Server,

        [Parameter(Mandatory)]
        [string]$Filter,

        [pscredential]$Credential
    )
    return [ADDCConnection]::new($Server,$Credential).NewADUserConnectionsByFilter($Filter)
}


function New-ADUserConnectionByIdentity {
    param (
        [Parameter(Mandatory)]
        [string]$Server,

        [Parameter(Mandatory)]
        [string]$Identity,

        [pscredential]$Credential
    )
    return [ADDCConnection]::new($Server,$Credential).NewADUserConnectionByIdentity($Identity)
}


<#
    represents an existing ADUser in Active Ditectory
#>
class ADUserConnection {
    hidden [guid]$ID
    [ADDCConnection]$DC
    [bool]$AllowUnsafeSets = $true

    ADUserConnection([ADDCConnection]$DC, $ObjectGuid) {
        $this.DC = $DC
        $this.ID = $ObjectGuid
    }

    
    [hashtable] Get([string[]]$Properties) {
        return $this.DC.GetADUserProperties($this.ID, $Properties)
    }
    [psobject] GetOne([string]$Property) {
        [hashtable]$results = $this.Get($Property)
        return $results[$Property]
    }
    Set([string]$Property, [psobject]$Value) {
        $this.set(@{$Property = $Value})
    }
    Set([hashtable]$Properties) {
        $SafeSets = @{}
        $HasSafeSets = $false
        foreach ($Key in $Properties.Keys) {
            $Value = $Properties[$Key]
            if ($this.IsSafeSettableProperty($Key)) {
                $SafeSets.Add($Key, $Value)
                $HasSafeSets = $true
            }
            # perform unsafe sets first, and one at a time.
            elseif ($this.AllowUnsafeSets) {
                $this.UnsafeSet($Key, $Value)
            }
        }
        if ($HasSafeSets) {
            $this.DC.SetADUserProperties($SafeSets)
        }
    }

    # this will allow internal setters to skipping the unsafe checking
    set([ADUserProperty]$Property, $Value) {
        $this.DC.SetADUserProperties($this.ID, @{$Property = $Value})
    }

    hidden [bool] IsSafeSettableProperty([string]$Property) {
        $Properties = [ADUserProperty].GetFields().Name | Where-Object {$psitem -ne 'value__'} 
        if ( $Properties -contains $Property) {
            return $true
        }
        return $false
    }

    # to be used on domain specific aduser properties 
    hidden UnsafeSet([string]$Property, $Value) {
        $CMD = @{}

        # Custom Property
        if ($Property -eq 'AccountPassword') {
            if ($Value -isnot [SecureString]) {
                $Value = ConvertTo-SecureString -String $Value -AsPlainText -Force
            } 
            $this.DC.SetADUserPassword($this.id, $Value)
        }
        # Null
        elseif ($Value -is [dbnull] -or $null -eq $Value) {
            $CMD = @{Clear = @($Property)}
        }
        # default. allow enduser to make decision
        else {
            $CMD = @{Replace = @{$Property = $Value}}
        }

        $this.DC.SetADUserProperties($this.ID, $CMD)
    }

    
    
    
    ##################################### Property Getters #####################################
    ############################################################################################
    
    [guid] ObjectGuid () {return $this.ID}
    [string[]] MemberOf () { return $this.GetOne('MemberOf')}

    [nullable[DateTime]] AccountExpirationDate () { return $this.GetOne('AccountExpirationDate')}
    [Boolean] AccountNotDelegated () { return $this.GetOne('AccountNotDelegated')}
    [Boolean] AllowReversiblePasswordEncryption () { return $this.GetOne('AllowReversiblePasswordEncryption')}
    [psobject] AuthenticationPolicy () { return $this.GetOne('AuthenticationPolicy')}
    [psobject] AuthenticationPolicySilo () { return $this.GetOne('AuthenticationPolicySilo')}
    [Boolean] CannotChangePassword () { return $this.GetOne('CannotChangePassword')}
    [Hashtable] Certificates () { return $this.GetOne('Certificates')}
    [Boolean] ChangePasswordAtLogon () { return $this.GetOne('ChangePasswordAtLogon')}
    [string] City () { return $this.GetOne('City')}
    [string] Company () { return $this.GetOne('Company')}
    [bool] CompoundIdentitySupported () { return $this.GetOne('CompoundIdentitySupported')}
    [string] Country () { return $this.GetOne('Country')}
    [string] Department () { return $this.GetOne('Department')}
    [string] Description () { return $this.GetOne('Description')}
    [string] DisplayName () { return $this.GetOne('DisplayName')}
    [string] Division () { return $this.GetOne('Division')}
    [string] EmailAddress () { return $this.GetOne('EmailAddress')}
    [string] EmployeeID () { return $this.GetOne('EmployeeID')}
    [string] EmployeeNumber () { return $this.GetOne('EmployeeNumber')}
    [bool] Enabled () { return $this.GetOne('Enabled')}
    [string] Fax () { return $this.GetOne('Fax')}
    [string] GivenName () { return $this.GetOne('GivenName')}
    [string] HomeDirectory () { return $this.GetOne('HomeDirectory')}
    [string] HomeDrive () { return $this.GetOne('HomeDrive')}
    [string] HomePage () { return $this.GetOne('HomePage')}
    [string] HomePhone () { return $this.GetOne('HomePhone')}
    [string] Initials () { return $this.GetOne('Initials')}
    [psobject] KerberosEncryptionType () { return $this.GetOne('KerberosEncryptionType')}
    [string] LogonWorkstations () { return $this.GetOne('LogonWorkstations')}
    [psobject] Manager () { return $this.GetOne('Manager')}
    [string] MobilePhone () { return $this.GetOne('MobilePhone')}
    [string] Office () { return $this.GetOne('Office')}
    [string] OfficePhone () { return $this.GetOne('OfficePhone')}
    [string] Organization () { return $this.GetOne('Organization')}
    [string] OtherName () { return $this.GetOne('OtherName')}
    [string] Partition () { return $this.GetOne('Partition')}
    [bool] PasswordNeverExpires () { return $this.GetOne('PasswordNeverExpires')}
    [bool] PasswordNotRequired () { return $this.GetOne('PasswordNotRequired')}
    [string] POBox () { return $this.GetOne('POBox')}
    [string] PostalCode () { return $this.GetOne('PostalCode')}
    [psobject] PrincipalsAllowedToDelegateToAccount () { return $this.GetOne('PrincipalsAllowedToDelegateToAccount')}
    [string] ProfilePath () { return $this.GetOne('ProfilePath')}
    [string] SamAccountName () { return $this.GetOne('SamAccountName')}
    [string] ScriptPath () { return $this.GetOne('ScriptPath')}
    [hashtable] ServicePrincipalNames () { return $this.GetOne('ServicePrincipalNames')}
    [bool] SmartcardLogonRequired () { return $this.GetOne('SmartcardLogonRequired')}
    [string] State () { return $this.GetOne('State')}
    [string] StreetAddress () { return $this.GetOne('StreetAddress')}
    [string] Surname () { return $this.GetOne('Surname')}
    [string] Title () { return $this.GetOne('Title')}
    [bool] TrustedForDelegation () { return $this.GetOne('TrustedForDelegation')}
    [string] UserPrincipalName () { return $this.GetOne('UserPrincipalName')}
    
    [Int64] accountExpires() {
        return $this.GetOne('accountExpires')
    }
    
    [nullable[datetime]]AccountLockoutTime() {return $this.GetOne('AccountLockoutTime')}
    [int] BadLogonCount() {return $this.GetOne('BadLogonCount')}
    [Int64] badPasswordTime() {return $this.GetOne('badPasswordTime')}
    [Int32] badPwdCount() {return $this.GetOne('badPwdCount')}
    [string] CanonicalName() {return $this.GetOne('CanonicalName')}
    [string] CN() {return $this.GetOne('CN')}
    [Int64] codePage() {return $this.GetOne('codePage')}
    [Int32] countryCode() {return $this.GetOne('countryCode')}
    [datetime] Created() {return $this.GetOne('Created')}
    [datetime] createTimeStamp() {return $this.GetOne('createTimeStamp')}
    [psobject] Deleted() {return $this.GetOne('Deleted')} #???
    [string] DistinguishedName() {return $this.GetOne('DistinguishedName')}
    [bool] DoesNotRequirePreAuth() {return $this.GetOne('DoesNotRequirePreAuth')}
    [bool] HomedirRequired() {return $this.GetOne('HomedirRequired')}
    [Int32] instanceType() {return $this.GetOne('instanceType')}
    [psobject] isDeleted() {return $this.GetOne('isDeleted')} #???
    [Nullable[datetime]] LastBadPasswordAttempt() {return $this.GetOne('LastBadPasswordAttempt')}
    [psobject] LastKnownParent() {return $this.GetOne('LastKnownParent')} #???
    [Int64] lastLogoff() {return $this.GetOne('lastLogoff')}
    [Int64] lastLogon() {return $this.GetOne('lastLogon')} 
    [Nullable[datetime]] LastLogonDate() {return $this.GetOne('LastLogonDate')} 
    [bool] LockedOut() {return $this.GetOne('LockedOut')} 
    [Int32] logonCount() {return $this.GetOne('logonCount')} 
    [datetime] Modified() {return $this.GetOne('Modified')} 
    [datetime] modifyTimeStamp() {return $this.GetOne('modifyTimeStamp')} 
    [string] Name() {return $this.GetOne('Name')} 
    [string] ObjectCategory() {return $this.GetOne('ObjectCategory')} 
    [string] ObjectClass() {return $this.GetOne('ObjectClass')} 
    [System.Security.Principal.SecurityIdentifier] objectSid() {return $this.GetOne('objectSid')} 
    [bool] PasswordExpired() {return $this.GetOne('PasswordExpired')} 
    [Nullable[datetime]] PasswordLastSet() {return $this.GetOne('PasswordLastSet')} 
    [string] PrimaryGroup() {return $this.GetOne('PrimaryGroup')} 
    [Int32] primaryGroupID() {return $this.GetOne('primaryGroupID')} 
    [bool] ProtectedFromAccidentalDeletion() {return $this.GetOne('ProtectedFromAccidentalDeletion')} 
    [Int64] pwdLastSet() {return $this.GetOne('pwdLastSet')}
    [Int32] sAMAccountType() {return $this.GetOne('sAMAccountType')}
    [System.Security.Principal.SecurityIdentifier] SID() {return $this.GetOne('SID')}
    [psobject] SIDHistory() {return $this.GetOne('SIDHistory')} #???
    [bool] TrustedToAuthForDelegation() {return $this.GetOne('TrustedToAuthForDelegation')}
    [Int32] userAccountControl() {return $this.GetOne('userAccountControl')}
    [psobject] userCertificate() {return $this.GetOne('userCertificate')}



    ##################################### Property Setters #####################################
    ############################################################################################

    # AccountPassword accepts securestring for the security freaks
    AccountPassword([securestring]$Password) {
        $this.DC.SetADUserPassword($this.id, $Password)
    }
    # AccountPassword accepts a string and secures it for you
    AccountPassword([string]$Password) {
        $SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
        $this.DC.SetADUserPassword($this.id, $SecurePassword)
    }
    MemberOf([guid[]]$NewMemberOf) {
        $CurrentMemberOf = $this.MemberOfGuids()
        [system.collections.Arraylist]$AddMemberOfs = @()
        [system.collections.Arraylist]$RemoveMemberOfs = @()
        
        # find memberOf to add
        foreach($Group in $NewMemberOf){
            if($CurrentMemberOf -notcontains $Group){
                $AddMemberOfs.Add($Group)
            }
        }
        if($AddMemberOfs){
            $this.DC.AddADPrincipalGroupMembership($this.ID,$AddMemberOfs)
        }
        
        # find memberOf to remove
        foreach($Group in $CurrentMemberOf){
            if($NewMemberOf -notcontains $Group){
                $RemoveMemberOfs.Add($Group)
            }
        }
        if($RemoveMemberOfs){
            $this.DC.RemoveADPrincipalGroupMembership($this.ID,$RemoveMemberOfs)
        }
    }
    MemberOf([String[]]$NewMemberOfIdentities){
        [guid[]]$NewMemberOf = @()
        foreach($Group in $NewMemberOfIdentities){
            [guid[]]$NewMemberOf += $this.dc.GetADGroupByIdentity($Group,'ObjectGuid').ObjectGuid
        }
        $this.MemberOf($NewMemberOf)
    }

    [guid[]] MemberOfGuids(){
        $CurrentMemberOf = $this.MemberOf()
        [guid[]] $CurrentMemberOfGuids = @()
        foreach($Group in $CurrentMemberOf){
            [guid[]] $CurrentMemberOfGuids += $this.DC.GetADGroupByIdentity($Group,'ObjectGuid').ObjectGuid
        }
        return $CurrentMemberOfGuids 
    }

    # AccountExpirationDate can be set by explicitly passing a datetime
    # AccountExpirationDate can be cleared implicity by passing a null
    AccountExpirationDate ([nullable[DateTime]]$Value) { 
        if ($null -eq $Value) {
            $this.DB.ClearADAccountExpiration($this.ID)
        }
        $this.Set([ADUserProperty]::AccountExpirationDate , $Value) 
    }

    # AccountExpirationDate can be cleared explicitly by passing a false boolean
    # AccountExpirationDate can be set implicity by passing a true boolean
    AccountExpirationDate ([bool]$Expiration) {
        if (!$Expiration) {
            $this.DB.ClearADAccountExpiration($this.ID)
        }
        else {
            $dt = Get-Date
            $this.AccountExpirationDate($dt)
        }
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