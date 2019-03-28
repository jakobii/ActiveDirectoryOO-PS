
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
            if ($Include -and $Include -NotContains $Key) {
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
            if ($Include -and $Include -NotContains $Key) {
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
            if ($Include -and $Include -NotContains $Key) {
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





class ADDCConnection {
    [string]$Server
    [pscredential]$Credential

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
    SetADUser([guid]$ObjectGuid, [hashtable]$Properties) {
        $Auth = $this.AuthSplat()
        Set-Aduser @Auth @Properties
    }
    [psobject] GetADUser([guid]$ObjectGuid, [string[]]$Properties) {
        $Auth = $this.AuthSplat()
        return Get-Aduser @Auth -Identity $ObjectGuid -Properties $Properties
    }
    SetADUserPassword([guid]$ObjectGuid, [securestring]$Password) {
        $Auth = $this.AuthSplat()
        Set-ADAccountPassword @Auth -Identity $ObjectGuid -Reset -Confirm:$False -NewPassword $Password
    }
    ClearADAccountExpiration([guid]$ObjectGuid) {
        $Auth = $this.AuthSplat()
        Clear-ADAccountExpiration @Auth -Identity $ObjectGuid -Confirm:$False
    }
    AddADPrincipalGroupMembership([guid]$ObjectGuid,[guid[]]$Groups){
        $Auth = $this.AuthSplat()
        Add-ADPrincipalGroupMembership @Auth -Identity $ObjectGuid -MemberOf $Groups
    }
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
        $this.ID = $this.ObjectGuid()
    }

    
    [hashtable] Get([string[]]$Properties) {
        $User = $this.DC.GetADUser($this.ID, $Properties)
        [hashtable]$HT = ConvertTo-Hashtable $User -Include $Properties
        return $HT
    }
    [psobject] Get([string]$Property) {
        [hashtable]$results = $this.get(@($Property))
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
            $this.DC.SetADUser($SafeSets)
        }
    }

    # this will allow internal setters to skipping the unsafe checking
    set([ADUserProperty]$Property, $Value) {
        $this.DC.SetADUser($this.ID, @{$Property = $Value})
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

        $this.DC.SetADUser($this.ID, $CMD)
    }

    
    
    
    ##################################### Property Getters #####################################
    ############################################################################################
    
    [guid] ObjectGuid () {return $this.ID}
    [string[]] MemberOf () { return $this.get('MemberOf')}

    [DateTime] AccountExpirationDate () { return $this.Get('AccountExpirationDate')}
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

    # AccountPassword accepts securestring for the security freaks
    AccountPassword([securestring]$Password) {
        $this.DC.SetADUserPassword($this.id, $Password)
    }
    # AccountPassword accepts a string and secures it for you
    AccountPassword([string]$Password) {
        $SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
        $this.DC.SetADUserPassword($this.id, $SecurePassword)
    }
    MemberOf([string[]]$Values) {

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