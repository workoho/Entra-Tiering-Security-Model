<#PSScriptInfo
.VERSION 1.0.0
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
    Version 1.0.0 (2024-05-19)
    - Initial release.
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

.PARAMETER IncludeSoftDeleted
    Specifies whether to include soft-deleted accounts.
    Note that the following parameters are not applied to soft-deleted accounts: ActiveDays, InactiveDays, DisabledOnly, and EnabledOnly.

.PARAMETER SoftDeletedOnly
    Specifies whether to retrieve only soft-deleted accounts.
    Note that the following parameters are not applied to soft-deleted accounts: ActiveDays, InactiveDays, DisabledOnly, and EnabledOnly.

.PARAMETER VerifiedDomains
    Specifies the verified domains of the organization. If not provided, the script will retrieve the verified domains from the Microsoft Graph API.

.PARAMETER OutJson
    Specifies whether to output the result as JSON.

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
    [boolean] $IncludeSoftDeleted,
    [boolean] $SoftDeletedOnly,
    [object] $VerifiedDomains,
    [boolean] $OutJson,
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
                if (($null -eq $ReferralUserId -and $null -ne $_) -or ($null -ne $ReferralUserId -and $null -eq $_)) {
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
        [boolean] $EnabledOnly,

        # Specifies whether to include soft-deleted accounts.
        # Note that the following parameters are not applied to soft-deleted accounts: ActiveDays, InactiveDays, DisabledOnly, and EnabledOnly.
        [boolean] $IncludeSoftDeleted,

        # Specifies whether to retrieve only soft-deleted accounts.
        # Note that the following parameters are not applied to soft-deleted accounts: ActiveDays, InactiveDays, DisabledOnly, and EnabledOnly.
        [boolean] $SoftDeletedOnly
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
        'id'
        'userPrincipalName'
        'displayName'
        'accountEnabled'
        'mail'
        'onPremisesExtensionAttributes'
        'signInActivity'
        'deletedDateTime'
    )

    $params = @{
        Method      = 'GET'
        Headers     = @{
            ConsistencyLevel = 'eventual'
        }
        Uri         = $null
        OutputType  = 'PSObject'
        ErrorAction = 'Stop'
        Verbose     = $false
        Debug       = $false
    }
    #endregion -----------------------------------------------------------------

    #region Get soft-deleted cloud admin accounts ------------------------------
    if ($IncludeSoftDeleted -or $SoftDeletedOnly) {
        Write-Verbose "[GetCloudAdminAccountsByTier]: - Retrieving soft-deleted cloud admin accounts for Tier $Tier."

        $params.Uri = 'https://graph.microsoft.com/beta/directory/deletedItems/microsoft.graph.user?$count=true&$filter={0}&$select={1}' -f $($filter -join ' and '), $($select -join ',')
        $response = Invoke-MgGraphRequestWithRetry $params

        while ($response) {
            $response.value

            if ($response.'@odata.nextLink') {
                $params.Uri = $response.'@odata.nextLink'
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

        if ($SoftDeletedOnly) { return }
    }
    #endregion -----------------------------------------------------------------

    #region Get cloud admin accounts -------------------------------------------
    if ($DisabledOnly) {
        Write-Verbose "[GetCloudAdminAccountsByTier]: - Applying accountEnabled=false filter."
        $filter += 'accountEnabled eq false'
    }

    if ($EnabledOnly) {
        Write-Verbose "[GetCloudAdminAccountsByTier]: - Applying accountEnabled=true filter."
        $filter += 'accountEnabled eq true'
    }

    Write-Verbose "[GetCloudAdminAccountsByTier]: - Retrieving cloud admin accounts for Tier $Tier."

    $params.Uri = 'https://graph.microsoft.com/beta/users?$count=true&$filter={0}&$select={1}' -f $($filter -join ' and '), $($select -join ',')
    $response = Invoke-MgGraphRequestWithRetry $params

    while ($response) {
        if ($ActiveDays -or $InactiveDays) {
            $response.value | & {
                process {
                    if ($_.signInActivity.lastSuccessfulSignInDateTime -eq $null) {
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

                    # Return the object to the pipeline
                    $_
                }
            }
        }
        else {
            # Return the object to the pipeline
            $response.value
        }

        if ($response.'@odata.nextLink') {
            $params.Uri = $response.'@odata.nextLink'
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
                throw $_
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
                $refUserObj = Get-MgUser -UserId $LocalUserId[$_] -ErrorAction Stop
            }
            catch {
                [void] $returnError.Add(( ./Common_0000__Write-Error.ps1 @{
                            Message           = "Get-MgUser failed for ReferralUserId-${_}: $($ReferralUserId[$_])"
                            ErrorId           = '400'
                            Category          = 'InvalidData'
                            RecommendedAction = 'Check the account and its reference value.'
                            CategoryActivity  = 'Account Status Sync'
                            CategoryReason    = "Get-MgUser failed for ReferralUserId-${_}: $($ReferralUserId[$_])"
                        }))
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
                            IncludeSoftDeleted               = $IncludeSoftDeleted
                            SoftDeletedOnly                  = $SoftDeletedOnly
                            ReferralUserId                   = $refUserObj.Id
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
                Tier                         = $_
                TierPrefix                   = $TierPrefix[$_]
                TierPrefixExtensionAttribute = $AccountTypeExtensionAttribute
                InitialTenantDomain          = $InitialTenantDomain
                ActiveDays                   = $ActiveDays
                InactiveDays                 = $InactiveDays
                DisabledOnly                 = $DisabledOnly
                EnabledOnly                  = $EnabledOnly
                IncludeSoftDeleted           = $IncludeSoftDeleted
                SoftDeletedOnly              = $SoftDeletedOnly
            }
            [void] $return.AddRange(@(Get-CloudAdminAccountsByTier @params))
        }
    }
}
Write-Verbose "[GetCloudAdminAccount]: - Found $($return.Count) dedicated cloud administrator accounts."
#endregion ---------------------------------------------------------------------

if ($return.Count -eq 0) {
    Write-Information 'No cloud admin accounts found.' -InformationAction Continue
}

Get-Variable | Where-Object { $StartupVariables -notcontains $_.Name } | & { process { Remove-Variable -Scope 0 -Name $_.Name -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue -Verbose:$false -Debug:$false -Confirm:$false -WhatIf:$false } }        # Delete variables created in this script to free up memory for tiny Azure Automation sandbox
if ($PSCommandPath) { Write-Verbose "-----END of $((Get-Item $PSCommandPath).Name) ---" }

if ($OutJson) { ./Common_0000__Write-JsonOutput.ps1 $return; return }
if ($OutText) { $return.userPrincipalName; return }

return $return
