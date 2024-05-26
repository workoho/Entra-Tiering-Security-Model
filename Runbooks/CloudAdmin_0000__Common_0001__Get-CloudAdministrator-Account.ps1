<#PSScriptInfo
.VERSION 1.1.0
.GUID 04a626b1-2f12-4afa-a789-76e97898cf5b
.AUTHOR Julian Pawlowski
.COMPANYNAME Workoho GmbH
.COPYRIGHT © 2024 Workoho GmbH
.TAGS
.LICENSEURI https://github.com/workoho/Entra-Tiering-Security-Model/blob/main/LICENSE.txt
.PROJECTURI https://github.com/workoho/Entra-Tiering-Security-Model
.ICONURI
.EXTERNALMODULEDEPENDENCIES Microsoft.Graph.Authentication
.REQUIREDSCRIPTS CloudAdmin_0000__Common_0000__Get-ConfigurationConstants.ps1
.EXTERNALSCRIPTDEPENDENCIES https://github.com/workoho/AzAuto-Common-Runbook-FW
.RELEASENOTES
    Version 1.1.0 (2024-05-26)
    - Add CSV output option.
    - Add ResolveReferralUserId parameter.
    - Use batch requests to improve performance.
    - Always request soft-deleted cloud admin accounts and remove respective parameters.
#>

<#
.SYNOPSIS
    Retrieves cloud admin accounts based on the specified tier.

.DESCRIPTION
    This script retrieves cloud admin accounts from the Microsoft Graph API based on the specified tier and tier prefix.
    It can also filter the accounts based on a referral user ID.

.PARAMETER ReferralUserId
    Specifies the object ID of the referral user identifying that the cloud admin account is associated with this user.

.PARAMETER Tier
    Specifies the tier level of the cloud admin accounts to get. Should be a value between 0 and 2.

.PARAMETER ActiveDays
    Specifies the number of days to consider an account active. If the account has not been active in the last ActiveDays, it will be filtered out.
    If ActiveDays is less than 1, the comparison will be done based on the last successful sign-in date and time.
    If ActiveDays is greater than or equal to 1, the comparison will be done based on the last successful sign-in date only.

.PARAMETER InactiveDays
    Specifies the number of days to consider an account inactive. If the account has been active in the last InactiveDays, it will be filtered out.
    If InactiveDays is less than 1, the comparison will be done based on the last successful sign-in date and time.
    If InactiveDays is greater than or equal to 1, the comparison will be done based on the last successful sign-in date only.

.PARAMETER DisabledOnly
    Specifies whether to retrieve only disabled accounts.

.PARAMETER EnabledOnly
    Specifies whether to retrieve only enabled accounts.

.PARAMETER ResolveReferralUserId
    Specifies whether to resolve the object ID of the referral user.

.PARAMETER VerifiedDomains
    Specifies the verified domains of the organization. If not provided, the script will retrieve the verified domains from the Microsoft Graph API.

.PARAMETER OutJson
    Specifies whether to output the result as JSON.

.PARAMETER OutCsv
    Specifies whether to output the result as CSV.

.PARAMETER OutText
    Specifies whether to output the result as text.
#>

[CmdletBinding()]
Param (
    [array] $ReferralUserId,
    [array] $Tier,
    [double] $ActiveDays,
    [double] $InactiveDays,
    [boolean] $DisabledOnly,
    [boolean] $EnabledOnly,
    [boolean] $ResolveReferralUserId,
    [object] $VerifiedDomains,
    [boolean] $OutJson,
    [boolean] $OutCsv,
    [boolean] $OutText
)

if ($PSCommandPath) { Write-Verbose "---START of $((Get-Item $PSCommandPath).Name), $((Test-ScriptFileInfo $PSCommandPath | Select-Object -Property Version, Guid | & { process{$_.PSObject.Properties | & { process{$_.Name + ': ' + $_.Value} }} }) -join ', ') ---" }
$StartupVariables = (Get-Variable | & { process { $_.Name } })      # Remember existing variables so we can cleanup ours at the end of the script

#region [COMMON] PARAMETER VALIDATION ------------------------------------------
if (
    ($ReferralUserId.Count -gt 1) -and
    ($ReferralUserId.Count -ne $Tier.Count)
) {
    Throw 'ReferralUserId and Tier must contain the same number of items for batch processing.'
}

if ($DisabledOnly -eq $true -and $EnabledOnly -eq $true) {
    Throw "Invalid parameters: 'DisabledOnly' and 'EnabledOnly' cannot both be true at the same time."
}
#endregion ---------------------------------------------------------------------

#region [COMMON] FUNCTIONS -----------------------------------------------------
function Get-CloudAdminAccountsByTier {
    <#
    .SYNOPSIS
        Retrieves cloud admin accounts based on the specified tier.

    .DESCRIPTION
        This function retrieves cloud admin accounts from the Microsoft Graph API based on the specified tier and tier prefix.
        It can also filter the accounts based on a referral user ID.
    #>

    param(
        # Specifies the tier level of the cloud admin accounts to get. Should be a value between 0 and 2.
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 2)]
        [int] $Tier,

        # Specifies the extension attribute number that contains the TierPrefix to identify as a cloud admin account. Should be a value between 1 and 15.
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 15)]
        [int] $TierPrefixExtensionAttribute,

        # Specifies the prefix for the tier level used to identify the cloud admin accounts, e.g., 'A0C' for Tier 0. The TierPrefixExtensionAttribute value is expected to start with this prefix.
        [Parameter(Mandatory = $true)]
        [string] $TierPrefix,

        # Specifies the initial tenant domain of the current tenant. This is the first onmicrosoft.com domain of the tenant (in case you created others after initial tenant creation) and is used to filter out external accounts.
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?\.onmicrosoft\.com$')]
        [string] $InitialTenantDomain,

        # Specifies the extension attribute number that contains the object ID of the referral user. Should be a value between 1 and 15. If ReferralUserId is provided, this must also be provided, and vice versa. These two parameters are linked and must be defined together to ensure correct association with the referral user.
        [ValidateScript(
            {
                if ($null -ne $ResolveReferralUserId -and $null -eq $_) {
                    throw "ResolveReferralUserId and ReferralUserIdExtensionAttribute must be defined together."
                }
                if ($null -ne $ReferralUserId -and $null -eq $_) {
                    throw "ReferralUserId and ReferralUserIdExtensionAttribute must be defined together."
                }
                return $true
            }
        )]
        [ValidateRange(1, 15)]
        [int] $ReferralUserIdExtensionAttribute,

        # Specifies the object ID of the referral user identifying that the cloud admin account is associated with this user. If ReferralUserIdExtensionAttribute is provided, this must also be provided, and vice versa.
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [string] $ReferralUserId,

        # Specifies whether to resolve the object ID of the referral user.
        [boolean] $ResolveReferralUserId,

        # Specifies the number of days to consider an account active. If the account has not been active in the last ActiveDays, it will be filtered out.
        # If ActiveDays is less than 1, the comparison will be done based on the last successful sign-in date and time.
        # If ActiveDays is greater than or equal to 1, the comparison will be done based on the last successful sign-in date only.
        [ValidateRange(0, 10000)]
        [double] $ActiveDays,

        # Specifies the number of days to consider an account inactive. If the account has been active in the last InactiveDays, it will be filtered out.
        # If InactiveDays is less than 1, the comparison will be done based on the last successful sign-in date and time.
        # If InactiveDays is greater than or equal to 1, the comparison will be done based on the last successful sign-in date only.
        [ValidateRange(0, 10000)]
        [double] $InactiveDays,

        # Specifies whether to retrieve only disabled accounts.
        [boolean] $DisabledOnly,

        # Specifies whether to retrieve only enabled accounts.
        [boolean] $EnabledOnly
    )

    #region Generate request parameters ----------------------------------------
    $filter = @(
        "userType eq 'Member'",
        "not endsWith(userPrincipalName, '%23EXT%23@$InitialTenantDomain')",
        'onPremisesSecurityIdentifier eq null',
        "startsWith(onPremisesExtensionAttributes/extensionAttribute$TierPrefixExtensionAttribute, '$TierPrefix')"
    )
    if (-not [string]::IsNullOrEmpty($ReferralUserId)) {
        Write-Verbose "[GetCloudAdminAccountsByTier]: - Applying ReferralUserId filter."
        $filter += "onPremisesExtensionAttributes/extensionAttribute$ReferralUserIdExtensionAttribute eq '$ReferralUserId'"
    }

    $select = @(
        'displayName'
        'userPrincipalName'
        'id'
        'accountEnabled'
        'deletedDateTime'
        'mail'
        'signInActivity'
        'onPremisesExtensionAttributes'
    )

    $params = @{
        Method      = 'POST'
        Uri         = 'https://graph.microsoft.com/v1.0/$batch'
        Body        = @{
            requests = [System.Collections.ArrayList] @(

                # Get cloud admin accounts
                @{
                    id      = 1
                    method  = 'GET'
                    headers = @{
                        ConsistencyLevel = 'eventual'
                    }
                    url     = '/users?$count=true&$filter={0}&$select={1}' -f $(
                        $filter + @(
                            if ($EnabledOnly) {
                                Write-Verbose "[GetCloudAdminAccountsByTier]: - Applying accountEnabled=true filter."
                                'accountEnabled eq true'
                            }
                            elseif ($DisabledOnly) {
                                Write-Verbose "[GetCloudAdminAccountsByTier]: - Applying accountEnabled=false filter."
                                'accountEnabled eq false'
                            }
                        ) -join ' and '
                    ), $($select -join ',')
                }

                # Get soft-deleted cloud admin accounts
                @{
                    id      = 2
                    method  = 'GET'
                    headers = @{
                        ConsistencyLevel = 'eventual'
                    }
                    url     = '/directory/deletedItems/microsoft.graph.user?$count=true&$filter={0}&$select={1}' -f $($filter -join ' and '), $($select -join ',')
                }
            )
        }
        OutputType  = 'PSObject'
        ErrorAction = 'Stop'
        Verbose     = $false
        Debug       = $false
    }
    #endregion -----------------------------------------------------------------

    #region Get cloud admin accounts -------------------------------------------
    Write-Verbose "[GetCloudAdminAccountsByTier]: - Retrieving cloud admin accounts for Tier $Tier."
    $response = Invoke-MgGraphRequestWithRetry $params

    while ($response) {
        $response.responses | & {
            process {
                $_.body.value | & {
                    process {
                        if ($ActiveDays -or $InactiveDays) {
                            if ($null -eq $_.signInActivity.lastSuccessfulSignInDateTime) {
                                Write-Verbose "[GetCloudAdminAccount]: - Filter out account $($_.userPrincipalName) due to missing lastSuccessfulSignInDateTime."
                                return
                            }

                            if ($ActiveDays) {
                                if ($_.signInActivity.lastSuccessfulSignInDateTime -lt $(
                                        # Subtracting days from the current date and current time for intra-day comparison
                                        if ($ActiveDays -lt 1) {
                                            [DateTime]::UtcNow.AddDays(-$ActiveDays)
                                        }

                                        # Subtracting days from the current date and setting the time to 00:00:00
                                        else {
                                            [DateTime]::UtcNow.Date.AddDays(-$ActiveDays)
                                        }
                                    )) {
                                    Write-Verbose "[GetCloudAdminAccount]: - Filter out account $($_.userPrincipalName) due to lack of activity in the last $ActiveDays days."
                                    return
                                }
                            }

                            if ($InactiveDays) {
                                if ($_.signInActivity.lastSuccessfulSignInDateTime -ge $(
                                        # Subtracting days from the current date and current time for intra-day comparison
                                        if ($InactiveDays -lt 1) {
                                            [DateTime]::UtcNow.AddDays(-$InactiveDays)
                                        }

                                        # Subtracting days from the current date and setting the time to 00:00:00
                                        else {
                                            [DateTime]::UtcNow.Date.AddDays(-$InactiveDays)
                                        }
                                    )) {
                                    Write-Verbose "[GetCloudAdminAccount]: - Filter out account $($_.userPrincipalName) due to activity in the last $InactiveDays days."
                                    return
                                }
                            }
                        }

                        $_ | Add-Member -NotePropertyName 'securityTierLevel' -NotePropertyValue $Tier

                        $_ | Add-Member -NotePropertyName 'refDisplayName' -NotePropertyValue $null
                        $_ | Add-Member -NotePropertyName 'refUserPrincipalName' -NotePropertyValue $null
                        $_ | Add-Member -NotePropertyName 'refOnPremisesSamAccountName' -NotePropertyValue $null
                        $_ | Add-Member -NotePropertyName 'refId' -NotePropertyValue $_.onPremisesExtensionAttributes."extensionAttribute$ReferralUserIdExtensionAttribute"
                        $_ | Add-Member -NotePropertyName 'refAccountEnabled' -NotePropertyValue $null
                        $_ | Add-Member -NotePropertyName 'refDeletedDateTime' -NotePropertyValue $null
                        $_ | Add-Member -NotePropertyName 'refMail' -NotePropertyValue $null
                        $_ | Add-Member -NotePropertyName 'refSignInActivity' -NotePropertyValue $null
                        $_ | Add-Member -NotePropertyName 'refManager' -NotePropertyValue $null
                        $_ | Add-Member -NotePropertyName 'refOnPremisesExtensionAttributes' -NotePropertyValue $null

                        if (
                            $ResolveReferralUserId -and
                            -Not [string]::IsNullOrEmpty($_.onPremisesExtensionAttributes."extensionAttribute$ReferralUserIdExtensionAttribute") -and
                            $_.onPremisesExtensionAttributes."extensionAttribute$ReferralUserIdExtensionAttribute" -match '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$'
                        ) {
                            Write-Verbose "[GetCloudAdminAccountByTier]: - Resolving referral user ID for account $($_.userPrincipalName)."
                            $obj = $_
                            try {
                                @(Get-ReferralUser -ReferralUserId $_.onPremisesExtensionAttributes."extensionAttribute$ReferralUserIdExtensionAttribute") | & {
                                    process {
                                        $_.PSObject.Properties | & {
                                            process {
                                                if ([string]::IsNullOrEmpty($_.Name)) { return }
                                                $obj.$('ref{0}{1}' -f $_.Name.Substring(0, 1).ToUpper(), $_.Name.Substring(1)) = $_.Value
                                            }
                                        }
                                    }
                                }
                            }
                            catch {
                                Throw $_
                            }
                        }

                        # Return the object to the pipeline
                        $_
                    }
                }
            }
        }

        if ($response.responses[1].body.'@odata.nextLink') {
            $params.Body.requests[1].url = $response.responses[1].body.'@odata.nextLink'
        }
        else {
            $params.Body.requests.RemoveAt(1)
        }

        if ($response.responses[0].body.'@odata.nextLink') {
            $params.Body.requests[0].url = $response.responses[0].body.'@odata.nextLink'
        }
        else {
            $params.Body.requests.RemoveAt(0)
        }

        if ($params.Body.requests.Count -gt 0) {
            $response = $null
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            $response = Invoke-MgGraphRequestWithRetry $params
        }
        else {
            $response = $null
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
        }
    }
    #endregion -----------------------------------------------------------------
}
function Get-ReferralUser {
    param(
        # Specifies the user principal name or object ID of the referral user.
        [Parameter(Mandatory = $true)]
        [string] $ReferralUserId
    )

    $filter = if ($ReferralUserId -match '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$') {
        "id eq '$($ReferralUserId)'"
    }
    else {
        "userPrincipalName eq '$([System.Web.HttpUtility]::UrlEncode($ReferralUserId))'"
    }

    $params = @{
        Method      = 'POST'
        Uri         = 'https://graph.microsoft.com/v1.0/$batch'
        Body        = @{
            requests = @(
                # First, search in existing users
                @{
                    id     = 1
                    method = 'GET'
                    url    = '/users?$filter={0}&$select={1}&$expand=manager($select={2})' -f $filter, $(
                        @(
                            'displayName'
                            'userPrincipalName'
                            'onPremisesSamAccountName'
                            'id'
                            'accountEnabled'
                            'deletedDateTime'
                            'mail'
                            'signInActivity'
                            'onPremisesExtensionAttributes'
                        ) -join ','
                    ), $(
                        @(
                            'displayName'
                            'userPrincipalName'
                            'onPremisesSamAccountName'
                            'id'
                            'accountEnabled'
                            'mail'
                        ) -join ','
                    )
                }

                # If not found, search in deleted items
                @{
                    id     = 2
                    method = 'GET'
                    url    = '/directory/deletedItems/microsoft.graph.user?$filter={0}&$select={1}&$expand=manager($select={2})' -f $filter, $(
                        @(
                            'displayName'
                            'userPrincipalName'
                            'id'
                            'accountEnabled'
                            'deletedDateTime'
                            'mail'
                            'signInActivity'
                            'onPremisesExtensionAttributes'
                        ) -join ','
                    ), $(
                        @(
                            'displayName'
                            'userPrincipalName'
                            'id'
                            'accountEnabled'
                            'mail'
                        ) -join ','
                    )
                }
            )
        }
        OutputType  = 'PSObject'
        ErrorAction = 'Stop'
        Verbose     = $false
        Debug       = $false
    }

    try {
        return (Invoke-MgGraphRequestWithRetry $params).responses | Sort-Object Id | & {
            process {
                if ($_.Id -eq 1) {
                    if ($null -ne $_.body.value) {
                        @($_.body.value)
                        return
                    }
                }
                else {
                    @($_.body.value)
                }
            }
        }
    }
    catch {
        Throw $_
    }
}
function Invoke-MgGraphRequestWithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $Params
    )

    do {
        try {
            $response = Invoke-MgGraphRequest @Params
            $rateLimitExceeded = $false
        }
        catch {
            if ($_.Exception.Response.StatusCode -eq 429) {
                $retryAfter = [int]$_.Exception.Response.Headers['Retry-After']
                Write-Verbose "Rate limit exceeded, retrying in $retryAfter seconds..."
                Start-Sleep -Seconds $retryAfter
                $rateLimitExceeded = $true
            }
            else {
                $errorMessage = $_.Exception.Response.Content.ReadAsStringAsync().Result | ConvertFrom-Json
                Throw "Error $($_.Exception.Response.StatusCode.value__) $($_.Exception.Response.StatusCode): [$($errorMessage.error.code)] $($errorMessage.error.message)"
            }
        }
    } while ($rateLimitExceeded)

    return $response
}
#endregion ---------------------------------------------------------------------

#region [COMMON] OPEN CONNECTIONS: Microsoft Graph -----------------------------
./Common_0001__Connect-MgGraph.ps1 -Scopes @(
    # Read-only permissions
    'AuditLog.Read.All'
    'Directory.Read.All'
    if ($null -eq $VerifiedDomains) { 'Organization.Read.All' }
)
#endregion ---------------------------------------------------------------------

#region [COMMON] ENVIRONMENT ---------------------------------------------------
./Common_0002__Import-AzAutomationVariableToPSEnv.ps1 1> $null      # Implicitly connects to Azure Cloud
$Constants = ./CloudAdmin_0000__Common_0000__Get-ConfigurationConstants.ps1
./Common_0000__Convert-PSEnvToPSScriptVariable.ps1 -Variable $Constants 1> $null
#endregion ---------------------------------------------------------------------

#region [COMMON] INITIALIZE SCRIPT VARIABLES -----------------------------------
if ([string]::IsNullOrEmpty($ReferenceExtensionAttribute)) {
    Throw 'ReferenceExtensionAttribute must not be null or empty.'
}
if ([string]::IsNullOrEmpty($AccountTypeExtensionAttributePrefix_Tier0)) {
    Throw 'AccountTypeExtensionAttributePrefix_Tier0 must not be null or empty.'
}
if ([string]::IsNullOrEmpty($AccountTypeExtensionAttributePrefix_Tier1)) {
    Throw 'AccountTypeExtensionAttributePrefix_Tier1 must not be null or empty.'
}
if ([string]::IsNullOrEmpty($AccountTypeExtensionAttributePrefix_Tier2)) {
    Throw 'AccountTypeExtensionAttributePrefix_Tier2 must not be null or empty.'
}
$TierPrefix = @(
    $AccountTypeExtensionAttributePrefix_Tier0
    $AccountTypeExtensionAttributePrefix_Tier1
    $AccountTypeExtensionAttributePrefix_Tier2
)

if ($null -eq $VerifiedDomains) {
    $VerifiedDomains = (Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization' -OutputType PSObject -ErrorAction Stop -Verbose:$false -Debug:$false).Value.VerifiedDomains
}
if (
    $null -ne $VerifiedDomains -and
    (
        $VerifiedDomains -isnot [array] -or
        $VerifiedDomains.Count -lt 1
    )
) {
    Throw 'VerifiedDomains must be an array containing the verified domains of the organization.'
}

$InitialTenantDomain = ($VerifiedDomains | Where-Object { $_.IsInitial -eq $true }).Name
if ([string]::IsNullOrEmpty($InitialTenantDomain)) {
    Throw 'Unable to find the initial tenant domain of the organization from VerifiedDomains array.'
}
Write-Verbose "[GetCloudAdminAccount]: - Detected initial tenant domain: $InitialTenantDomain"

$return = [System.Collections.ArrayList]::new()
#endregion ---------------------------------------------------------------------

#region Find Admin Accounts ----------------------------------------------------
if ($ReferralUserId) {
    $LocalUserId = @( ./Common_0002__Convert-UserIdToLocalUserId.ps1 -UserId $ReferralUserId -VerifiedDomains $VerifiedDomains )
    if ($LocalUserId.Count -ne $ReferralUserId.Count) { Throw 'ReferralUserId count must not be different after LocalUserId conversion.' }

    0..$($ReferralUserId.Count - 1) | & {
        process {
            if (
                ($null -eq $ReferralUserId[$_]) -or
                ($ReferralUserId[$_] -isnot [string]) -or
                [string]::IsNullOrEmpty( $ReferralUserId[$_].Trim() )
            ) {
                Write-Verbose "[GetCloudAdminAccount]: - ReferralUserId-$_ Type : $(($ReferralUserId[$_]).GetType().Name)"
                Write-Verbose "[GetCloudAdminAccount]: - ReferralUserId-$_ Value: '$($ReferralUserId[$_])'"
                Write-Warning "[GetCloudAdminAccount]: - Ignoring array item $_ because 'ReferralUserId' is not a string or IsNullOrEmpty"
                return
            }

            if (
                ($null -eq $LocalUserId[$_]) -or
                ($LocalUserId[$_] -isnot [string]) -or
                [string]::IsNullOrEmpty( $LocalUserId[$_].Trim() )
            ) {
                Write-Verbose "[GetCloudAdminAccount]: - LocalUserId-$_ Type : $(($LocalUserId[$_]).GetType().Name)"
                Write-Verbose "[GetCloudAdminAccount]: - LocalUserId-$_ Value: '$($LocalUserId[$_])'"
                Write-Warning "[GetCloudAdminAccount]: - Ignoring array item $_ because 'LocalUserId' is not a string or IsNullOrEmpty"
                return
            }

            if (
                ($null -ne $Tier) -and
                ($null -ne $Tier[$_]) -and
                ($Tier[$_] -is [string]) -and
                (-Not [string]::IsNullOrEmpty( $Tier[$_].Trim() ))
            ) {
                try {
                    $Tier[$_] = [System.Convert]::ToInt32( $Tier[$_].Trim() )
                }
                catch {
                    Write-Error '[GetCloudAdminAccount]: - Auto-converting of Tier string to Int32 failed'
                }
            }

            Write-Verbose "[GetCloudAdminAccount]: - Processing ReferralUserId-${_}: $($ReferralUserId[$_])"
            try {
                $refUserId = @(Get-ReferralUser -ReferralUserId $LocalUserId[$_])[0].Id
            }
            catch {
                Throw $_
            }

            if ($null -eq $refUserId) {
                Write-Warning "ReferralUserId '$($ReferralUserId[$_])' not found."
                return
            }

            $UserIndex = $_
            0..2 | & {
                process {
                    if (
                        $null -eq $Tier -or
                        [string]::IsNullOrEmpty( $Tier[$UserIndex] ) -or
                        $Tier[$UserIndex] -eq $_
                    ) {
                        $params = @{
                            Tier                             = $_
                            TierPrefix                       = $TierPrefix[$_]
                            TierPrefixExtensionAttribute     = $AccountTypeExtensionAttribute
                            InitialTenantDomain              = $InitialTenantDomain
                            ActiveDays                       = $ActiveDays
                            InactiveDays                     = $InactiveDays
                            DisabledOnly                     = $DisabledOnly
                            EnabledOnly                      = $EnabledOnly
                            ResolveReferralUserId            = $ResolveReferralUserId
                            ReferralUserId                   = $refUserId
                            ReferralUserIdExtensionAttribute = $ReferenceExtensionAttribute
                        }
                        [void] $return.AddRange(@(Get-CloudAdminAccountsByTier @params))
                    }
                }
            }
        }
    }
}
else {
    0..2 | & {
        process {
            if (
                $null -ne $Tier -and
                $_ -notin $Tier
            ) {
                return
            }

            $params = @{
                Tier                             = $_
                TierPrefix                       = $TierPrefix[$_]
                TierPrefixExtensionAttribute     = $AccountTypeExtensionAttribute
                InitialTenantDomain              = $InitialTenantDomain
                ActiveDays                       = $ActiveDays
                InactiveDays                     = $InactiveDays
                DisabledOnly                     = $DisabledOnly
                EnabledOnly                      = $EnabledOnly
                ResolveReferralUserId            = $ResolveReferralUserId
                ReferralUserIdExtensionAttribute = $ReferenceExtensionAttribute
            }
            [void] $return.AddRange(@(Get-CloudAdminAccountsByTier @params))
        }
    }
}
Write-Verbose "[GetCloudAdminAccount]: - Found $($return.Count) dedicated cloud administrator accounts."
#endregion ---------------------------------------------------------------------

Get-Variable | Where-Object { $StartupVariables -notcontains $_.Name } | & { process { Remove-Variable -Scope 0 -Name $_.Name -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue -Verbose:$false -Debug:$false -Confirm:$false -WhatIf:$false } }        # Delete variables created in this script to free up memory for tiny Azure Automation sandbox
if ($PSCommandPath) { Write-Verbose "-----END of $((Get-Item $PSCommandPath).Name) ---" }

if ($OutJson) { if ($return.Count -eq 0) { return '[]' }; ./Common_0000__Write-JsonOutput.ps1 $return; return }

if ($OutCsv) {
    if ($return.Count -eq 0) {
        return 'No cloud admin accounts found.'
    }
    $return | & {
        process {
            $_ | Add-Member -NotePropertyName 'lastSignInDateTime' -NotePropertyValue $_.signInActivity.lastSignInDateTime
            $_ | Add-Member -NotePropertyName 'lastNonInteractiveSignInDateTime' -NotePropertyValue $_.signInActivity.lastNonInteractiveSignInDateTime
            $_ | Add-Member -NotePropertyName 'lastSuccessfulSignInDateTime' -NotePropertyValue $_.signInActivity.lastSuccessfulSignInDateTime

            $_ | Add-Member -NotePropertyName 'extensionAttribute1' -NotePropertyValue $_.onPremisesExtensionAttributes.extensionAttribute1
            $_ | Add-Member -NotePropertyName 'extensionAttribute2' -NotePropertyValue $_.onPremisesExtensionAttributes.extensionAttribute2
            $_ | Add-Member -NotePropertyName 'extensionAttribute3' -NotePropertyValue $_.onPremisesExtensionAttributes.extensionAttribute3
            $_ | Add-Member -NotePropertyName 'extensionAttribute4' -NotePropertyValue $_.onPremisesExtensionAttributes.extensionAttribute4
            $_ | Add-Member -NotePropertyName 'extensionAttribute5' -NotePropertyValue $_.onPremisesExtensionAttributes.extensionAttribute5
            $_ | Add-Member -NotePropertyName 'extensionAttribute6' -NotePropertyValue $_.onPremisesExtensionAttributes.extensionAttribute6
            $_ | Add-Member -NotePropertyName 'extensionAttribute7' -NotePropertyValue $_.onPremisesExtensionAttributes.extensionAttribute7
            $_ | Add-Member -NotePropertyName 'extensionAttribute8' -NotePropertyValue $_.onPremisesExtensionAttributes.extensionAttribute8
            $_ | Add-Member -NotePropertyName 'extensionAttribute9' -NotePropertyValue $_.onPremisesExtensionAttributes.extensionAttribute9
            $_ | Add-Member -NotePropertyName 'extensionAttribute10' -NotePropertyValue $_.onPremisesExtensionAttributes.extensionAttribute10
            $_ | Add-Member -NotePropertyName 'extensionAttribute11' -NotePropertyValue $_.onPremisesExtensionAttributes.extensionAttribute11
            $_ | Add-Member -NotePropertyName 'extensionAttribute12' -NotePropertyValue $_.onPremisesExtensionAttributes.extensionAttribute12
            $_ | Add-Member -NotePropertyName 'extensionAttribute13' -NotePropertyValue $_.onPremisesExtensionAttributes.extensionAttribute13
            $_ | Add-Member -NotePropertyName 'extensionAttribute14' -NotePropertyValue $_.onPremisesExtensionAttributes.extensionAttribute14
            $_ | Add-Member -NotePropertyName 'extensionAttribute15' -NotePropertyValue $_.onPremisesExtensionAttributes.extensionAttribute15

            $_ | Add-Member -NotePropertyName 'refLastSignInDateTime' -NotePropertyValue $_.refSignInActivity.lastSignInDateTime
            $_ | Add-Member -NotePropertyName 'refLastNonInteractiveSignInDateTime' -NotePropertyValue $_.refSignInActivity.lastNonInteractiveSignInDateTime
            $_ | Add-Member -NotePropertyName 'refLastSuccessfulSignInDateTime' -NotePropertyValue $_.refSignInActivity.lastSuccessfulSignInDateTime

            $_ | Add-Member -NotePropertyName 'refExtensionAttribute1' -NotePropertyValue $_.refOnPremisesExtensionAttributes.extensionAttribute1
            $_ | Add-Member -NotePropertyName 'refExtensionAttribute2' -NotePropertyValue $_.refOnPremisesExtensionAttributes.extensionAttribute2
            $_ | Add-Member -NotePropertyName 'refExtensionAttribute3' -NotePropertyValue $_.refOnPremisesExtensionAttributes.extensionAttribute3
            $_ | Add-Member -NotePropertyName 'refExtensionAttribute4' -NotePropertyValue $_.refOnPremisesExtensionAttributes.extensionAttribute4
            $_ | Add-Member -NotePropertyName 'refExtensionAttribute5' -NotePropertyValue $_.refOnPremisesExtensionAttributes.extensionAttribute5
            $_ | Add-Member -NotePropertyName 'refExtensionAttribute6' -NotePropertyValue $_.refOnPremisesExtensionAttributes.extensionAttribute6
            $_ | Add-Member -NotePropertyName 'refExtensionAttribute7' -NotePropertyValue $_.refOnPremisesExtensionAttributes.extensionAttribute7
            $_ | Add-Member -NotePropertyName 'refExtensionAttribute8' -NotePropertyValue $_.refOnPremisesExtensionAttributes.extensionAttribute8
            $_ | Add-Member -NotePropertyName 'refExtensionAttribute9' -NotePropertyValue $_.refOnPremisesExtensionAttributes.extensionAttribute9
            $_ | Add-Member -NotePropertyName 'refExtensionAttribute10' -NotePropertyValue $_.refOnPremisesExtensionAttributes.extensionAttribute10
            $_ | Add-Member -NotePropertyName 'refExtensionAttribute11' -NotePropertyValue $_.refOnPremisesExtensionAttributes.extensionAttribute11
            $_ | Add-Member -NotePropertyName 'refExtensionAttribute12' -NotePropertyValue $_.refOnPremisesExtensionAttributes.extensionAttribute12
            $_ | Add-Member -NotePropertyName 'refExtensionAttribute13' -NotePropertyValue $_.refOnPremisesExtensionAttributes.extensionAttribute13
            $_ | Add-Member -NotePropertyName 'refExtensionAttribute14' -NotePropertyValue $_.refOnPremisesExtensionAttributes.extensionAttribute14
            $_ | Add-Member -NotePropertyName 'refExtensionAttribute15' -NotePropertyValue $_.refOnPremisesExtensionAttributes.extensionAttribute15

            $_ | Add-Member -NotePropertyName 'managerDisplayName' -NotePropertyValue $_.refManager.displayName
            $_ | Add-Member -NotePropertyName 'managerUserPrincipalName' -NotePropertyValue $_.refManager.userPrincipalName
            $_ | Add-Member -NotePropertyName 'managerOnPremisesSamAccountName' -NotePropertyValue $_.refManager.onPremisesSamAccountName
            $_ | Add-Member -NotePropertyName 'managerId' -NotePropertyValue $_.refManager.id
            $_ | Add-Member -NotePropertyName 'managerAccountEnabled' -NotePropertyValue $_.refManager.accountEnabled
            $_ | Add-Member -NotePropertyName 'managerMail' -NotePropertyValue $_.refManager.mail

            $_ | Select-Object -Property @(
                'securityTierLevel'
                'displayName'
                'userPrincipalName'
                'id'
                'accountEnabled'
                'deletedDateTime'
                'mail'
                'lastSignInDateTime'
                'lastNonInteractiveSignInDateTime'
                'lastSuccessfulSignInDateTime'
                'extensionAttribute1'
                'extensionAttribute2'
                'extensionAttribute3'
                'extensionAttribute4'
                'extensionAttribute5'
                'extensionAttribute6'
                'extensionAttribute7'
                'extensionAttribute8'
                'extensionAttribute9'
                'extensionAttribute10'
                'extensionAttribute11'
                'extensionAttribute12'
                'extensionAttribute13'
                'extensionAttribute14'
                'extensionAttribute15'
                'refDisplayName'
                'refUserPrincipalName'
                'refOnPremisesSamAccountName'
                'refId'
                'refAccountEnabled'
                'refDeletedDateTime'
                'refMail'
                'refLastSignInDateTime'
                'refLastNonInteractiveSignInDateTime'
                'refLastSuccessfulSignInDateTime'
                'refExtensionAttribute1'
                'refExtensionAttribute2'
                'refExtensionAttribute3'
                'refExtensionAttribute4'
                'refExtensionAttribute5'
                'refExtensionAttribute6'
                'refExtensionAttribute7'
                'refExtensionAttribute8'
                'refExtensionAttribute9'
                'refExtensionAttribute10'
                'refExtensionAttribute11'
                'refExtensionAttribute12'
                'refExtensionAttribute13'
                'refExtensionAttribute14'
                'refExtensionAttribute15'
                'managerDisplayName'
                'managerUserPrincipalName'
                'managerOnPremisesSamAccountName'
                'managerId'
                'managerAccountEnabled'
                'managerMail'
            )
        }
    } | & {
        process {
            if ($_.lastSignInDateTime) { $_.lastSignInDateTime = [DateTime]::Parse($_.lastSignInDateTime).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
            if ($_.lastNonInteractiveSignInDateTime) { $_.lastNonInteractiveSignInDateTime = [DateTime]::Parse($_.lastNonInteractiveSignInDateTime).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
            if ($_.lastSuccessfulSignInDateTime) { $_.lastSuccessfulSignInDateTime = [DateTime]::Parse($_.lastSuccessfulSignInDateTime).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }

            if ($_.refLastSignInDateTime) { $_.refLastSignInDateTime = [DateTime]::Parse($_.refLastSignInDateTime).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
            if ($_.refLastNonInteractiveSignInDateTime) { $_.refLastNonInteractiveSignInDateTime = [DateTime]::Parse($_.refLastNonInteractiveSignInDateTime).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
            if ($_.refLastSuccessfulSignInDateTime) { $_.refLastSuccessfulSignInDateTime = [DateTime]::Parse($_.refLastSuccessfulSignInDateTime).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }

            $_
        }
    } | ConvertTo-Csv -NoTypeInformation
    return
}

if ($OutText) { if ($return.Count -eq 0) { return 'No cloud admin accounts found.' }; $return.userPrincipalName; return }

if ($return.Count -eq 0) {
    Write-Information 'No cloud admin accounts found.' -InformationAction Continue
}

return $return
