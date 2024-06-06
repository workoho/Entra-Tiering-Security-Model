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
    Version 1.0.0 (2024-06-06)
    - use Common_0001__Invoke-MgGraphRequest.ps1 instead of Common_0002__Invoke-MgGraphRequest.ps1
#>

<#
.SYNOPSIS
    Retrieves cloud admin accounts either based on the specified tier, referral user ID, or both.

.DESCRIPTION
    This script retrieves cloud admin accounts from the Microsoft Graph API based on the specified security tier level, referral user ID, or both.

.PARAMETER ReferralUserId
    Specifies the object ID of the primary user account to search for all associated cloud admin accounts.
    May be an array, or a comma-separated string of object IDs or user principal names.
    If not provided, the script will retrieve all cloud admin accounts.

.PARAMETER Tier
    Specifies the security tier level of the cloud admin accounts to get. Must be a value between 0 and 2.
    If not provided, the script will search for all tiers.

    May be an array, or a comma-separated string of security tier levels.

.PARAMETER ActiveDays
    Specifies the number of days to consider an account active. If the account has not been active in the last ActiveDays, it will be filtered out.
    If ActiveDays is less than 1, the comparison will be done based on the last successful sign-in date and time.
    If ActiveDays is greater than or equal to 1, the comparison will be done based on the last successful sign-in date only.

.PARAMETER InactiveDays
    Specifies the number of days to consider an account inactive. If the account has been active in the last InactiveDays, it will be filtered out.
    If InactiveDays is less than 1, the comparison will be done based on the last successful sign-in date and time.
    If InactiveDays is greater than or equal to 1, the comparison will be done based on the last successful sign-in date only.
    Note that only accounts that have been signed in at least once will be considered.

.PARAMETER NeverUsedDays
    Specifies the number of days after account creation to consider an account never used. If the account has ever successfully signed in, or was created within the specified number of days, it will be filtered out.

.PARAMETER DisabledOnly
    Specifies whether to retrieve only disabled accounts.

.PARAMETER EnabledOnly
    Specifies whether to retrieve only enabled accounts.

.PARAMETER ExpandReferralUserId
    Specifies whether to include additional properties related to the referral user in the response.

.PARAMETER OutJson
    Specifies whether to output the result as JSON.

.PARAMETER OutCsv
    Specifies whether to output the result as CSV.
    The 'referralUserAccount' property will be expanded to include additional properties related to the primary user account.
    Note that for the information to be included in the CSV output, the 'ExpandReferralUserId' parameter must be set to $true.
    Also, the 'signInActivity' and 'onPremisesExtensionAttributes' properties are expanded into separate columns.

    If the AV_CloudAdmin_StorageUri variable is set in the Azure Automation account, the CSV file is stored in the specified Azure Blob Storage container or Azure File Share.
    The file name is prefixed with the current date and time in the format 'yyyyMMddTHHmmssfffZ'.
    Note that the managed identity of the Azure Automation account must have the necessary permissions to write to the specified storage account.
    That is, the managed identity must have the 'Storage Blob Data Contributor' role for a blob container or the 'Storage File Data SMB Share Contributor' role for a file share.
    Remember that general roles like 'Owner' or 'Contributor' do not grant write access to storage accounts.

.PARAMETER OutText
    Specifies whether to output the result as text.
    This will only output the user principal name of the cloud admin accounts.

.OUTPUTS
    Output may be requested in JSON, CSV, or text format by using one of the parameters -OutJson, -OutCsv, or -OutText.
    The output includes properties such as 'userPrincipalName', 'accountEnabled', 'lastSuccessfulSignInDateTime', etc.

    If none of these parameters are used, the script returns an object array where each object represents a cloud admin account.
    and its associated primary user account in the 'referralUserAccount' property.
#>

[CmdletBinding()]
Param (
    [array] $ReferralUserId,
    [array] $Tier,
    [double] $ActiveDays,
    [double] $InactiveDays,
    [double] $NeverUsedDays,
    [boolean] $DisabledOnly,
    [boolean] $EnabledOnly,
    [boolean] $ExpandReferralUserId,
    [boolean] $OutJson,
    [boolean] $OutCsv,
    [boolean] $OutText
)

if ($PSCommandPath) { Write-Verbose "---START of $((Get-Item $PSCommandPath).Name), $((Test-ScriptFileInfo $PSCommandPath | Select-Object -Property Version, Guid | & { process{$_.PSObject.Properties | & { process{$_.Name + ': ' + $_.Value} }} }) -join ', ') ---" }
$StartupVariables = (Get-Variable | & { process { $_.Name } })      # Remember existing variables so we can cleanup ours at the end of the script

#region [COMMON] PARAMETER VALIDATION ------------------------------------------

# Allow comma-separated values for ReferralUserId and Tier
$ReferralUserId = if ([string]::IsNullOrEmpty($ReferralUserId)) { @() } else {
    @($ReferralUserId) | & { process { $_ -split '\s*,\s*' } } | & { process { if (-not [string]::IsNullOrEmpty($_)) { $_ } } }
}
$Tier = if ([string]::IsNullOrEmpty($Tier)) { @() } else {
    @($Tier) | & { process { $_ -split '\s*,\s*' } } | & {
        process {
            if (-not [string]::IsNullOrEmpty($_)) {
                try {
                    [System.Convert]::ToInt32($_)
                    if ($_ -lt 0 -or $_ -gt 2) {
                        Throw 'Tier must be a value between 0 and 2.'
                    }
                }
                catch {
                    Throw "[GetCloudAdminAccountsByPrimaryAccount]: - Auto-converting of Tier string to Int32 failed: $_"
                }
            }
        }
    }
}

if (
    ($ReferralUserId.Count -gt 1) -and
    ($Tier.Count -gt 1) -and
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
                if ($null -ne $ExpandReferralUserId -and $null -eq $_) {
                    throw "ExpandReferralUserId and ReferralUserIdExtensionAttribute must be defined together."
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
        [boolean] $ExpandReferralUserId,

        # Specifies the number of days to consider an account active. If the account has not been active in the last ActiveDays, it will be filtered out.
        # If ActiveDays is less than 1, the comparison will be done based on the last successful sign-in date and time.
        # If ActiveDays is greater than or equal to 1, the comparison will be done based on the last successful sign-in date only.
        [ValidateRange(0, 10000)]
        [double] $ActiveDays,

        # Specifies the number of days to consider an account inactive. If the account has been active in the last InactiveDays, it will be filtered out.
        # If InactiveDays is less than 1, the comparison will be done based on the last successful sign-in date and time.
        # If InactiveDays is greater than or equal to 1, the comparison will be done based on the last successful sign-in date only.
        # Note that only accounts that have been signed in at least once will be considered.
        [ValidateRange(0, 10000)]
        [double] $InactiveDays,

        # Specifies the number of days after account creation to consider an account never used. If the account has ever successfully signed in, or was created within the specified number of days, it will be filtered out.
        [ValidateRange(0, 10000)]
        [double] $NeverUsedDays,

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
        Write-Verbose "[GetCloudAdminAccountsByPrimaryAccount]: - Applying ReferralUserId filter."
        $filter += "onPremisesExtensionAttributes/extensionAttribute$ReferralUserIdExtensionAttribute eq '$ReferralUserId'"
    }

    $select = @(
        'displayName'
        'userPrincipalName'
        'id'
        'accountEnabled'
        'createdDateTime'
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
                    url     = 'users?$count=true&$filter={0}&$select={1}' -f $(
                        $filter + @(
                            if ($EnabledOnly) {
                                Write-Verbose "[GetCloudAdminAccountsByPrimaryAccount]: - Applying accountEnabled=true filter."
                                'accountEnabled eq true'
                            }
                            elseif ($DisabledOnly) {
                                Write-Verbose "[GetCloudAdminAccountsByPrimaryAccount]: - Applying accountEnabled=false filter."
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
                    url     = 'directory/deletedItems/microsoft.graph.user?$count=true&$filter={0}&$select={1}' -f $($filter -join ' and '), $($select -join ',')
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
    Write-Verbose "[GetCloudAdminAccountsByPrimaryAccount]: - Retrieving cloud admin accounts for Tier $Tier."
    try {
        $response = ./Common_0001__Invoke-MgGraphRequest.ps1 $params
    }
    catch {
        Throw $_
    }

    $retryAfter = $null

    while ($response) {
        $response.responses | & {
            process {
                if ($_.status -eq 429) {
                    $retryAfter = if (-not $retryAfter -or $retryAfter -gt $_.Headers.'Retry-After') { [int] $_.Headers.'Retry-After' }
                }
                elseif ($_.status -eq 200) {
                    @($_.body.value) | & {
                        process {
                            if ($null -eq $_) { return }

                            if ($NeverUsedDays) {
                                if ($null -ne $_.signInActivity.lastSuccessfulSignInDateTime) {
                                    Write-Verbose "[GetCloudAdminAccount]: - Filter out account $($_.userPrincipalName) due to activity in the past."
                                    return
                                }

                                if ($_.createdDateTime -gt $(
                                        # Subtracting days from the current date and current time for intra-day comparison
                                        if ($NeverUsedDays -lt 1) {
                                            [DateTime]::UtcNow.AddDays(-$NeverUsedDays)
                                        }

                                        # Subtracting days from the current date and setting the time to 00:00:00
                                        else {
                                            [DateTime]::UtcNow.Date.AddDays(-$NeverUsedDays)
                                        }
                                    )) {
                                    Write-Verbose "[GetCloudAdminAccount]: - Filter out account $($_.userPrincipalName) due to creation date within the last $NeverUsedDays days at $([DateTime]::Parse($_.createdDateTime).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))."
                                    return
                                }
                            }

                            if ($ActiveDays) {
                                if ($null -eq $_.signInActivity.lastSuccessfulSignInDateTime) {
                                    Write-Verbose "[GetCloudAdminAccount]: - Filter out account $($_.userPrincipalName) due to missing lastSuccessfulSignInDateTime."
                                    return
                                }

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
                                if ($null -eq $_.signInActivity.lastSuccessfulSignInDateTime) {
                                    Write-Verbose "[GetCloudAdminAccount]: - Filter out account $($_.userPrincipalName) due to missing lastSuccessfulSignInDateTime."
                                    return
                                }

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

                            $_ | Add-Member -NotePropertyMembers @{
                                securityTierLevel = $Tier
                            }

                            if (
                                $ExpandReferralUserId -and
                                -Not [string]::IsNullOrEmpty($_.onPremisesExtensionAttributes."extensionAttribute$ReferralUserIdExtensionAttribute") -and
                                $_.onPremisesExtensionAttributes."extensionAttribute$ReferralUserIdExtensionAttribute" -match '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$'
                            ) {
                                Write-Verbose "[GetCloudAdminAccountByTier]: - Expanding referral user account for $($_.userPrincipalName)."
                                try {
                                    $_ | Add-Member -MemberType NoteProperty -Name 'referralUserAccount' -Value (
                                        @(./Common_0003__Find-MgUserWithSoftDeleted.ps1 -UserId $_.onPremisesExtensionAttributes."extensionAttribute$ReferralUserIdExtensionAttribute" -Property @(
                                                'displayName'
                                                'userPrincipalName'
                                                'onPremisesSamAccountName'
                                                'id'
                                                'accountEnabled'
                                                'createdDateTime'
                                                'deletedDateTime'
                                                'mail'
                                                'companyName'
                                                'department'
                                                'streetAddress'
                                                'city'
                                                'postalCode'
                                                'state'
                                                'country'
                                                'signInActivity'
                                                'onPremisesExtensionAttributes'
                                            ) -ExpandProperty @(
                                                @{
                                                    manager = @(
                                                        'displayName'
                                                        'userPrincipalName'
                                                        'id'
                                                        'accountEnabled'
                                                        'mail'
                                                    )
                                                }
                                            ))[0] | Where-Object { $_ -ne $null }
                                    )
                                }
                                catch {
                                    Throw $_
                                }
                            }
                            else {
                                $_ | Add-Member -MemberType NoteProperty -Name 'referralUserAccount' -Value (
                                    [PSCustomObject] @{
                                        id = $_.onPremisesExtensionAttributes."extensionAttribute$ReferralUserIdExtensionAttribute"
                                    }
                                )
                            }

                            # Return the object to the pipeline
                            $_
                        }
                    }

                    $responseId = $_.Id
                    $requestIndexId = $params.Body.requests.IndexOf(($params.Body.requests | Where-Object { $_.id -eq $responseId }))

                    if ($_.body.'@odata.nextLink') {
                        Write-Verbose "[GetCloudAdminAccount]: - Next link found for request ID $($_.Id)."
                        $params.Body.requests[$requestIndexId].url = $_.body.'@odata.nextLink' -replace '^https://graph.microsoft.com/v1.0/', ''
                    }
                    else {
                        $params.Body.requests.RemoveAt($requestIndexId)
                    }
                }
                else {
                    Throw "Error $($_.status): [$($_.body.error.code)] $($_.body.error.message)"
                }
            }
        }

        if ($params.Body.requests.Count -gt 0) {
            if ($retryAfter) {
                Write-Verbose "[GetCloudAdminAccount]: - Rate limit exceeded, waiting for $retryAfter seconds..."
                Start-Sleep -Seconds $retryAfter
            }
            else {
                Write-Verbose "[GetCloudAdminAccount]: - Sending next batch request."
            }
            $response = $null
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            try {
                $response = ./Common_0001__Invoke-MgGraphRequest.ps1 $params
            }
            catch {
                Throw $_
            }
        }
        else {
            Write-Verbose "[GetCloudAdminAccount]: - No more batch requests to send."
            $response = $null
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
        }
    }
    #endregion -----------------------------------------------------------------
}
#endregion ---------------------------------------------------------------------

#region [COMMON] OPEN CONNECTIONS: Microsoft Graph -----------------------------
./Common_0001__Connect-MgGraph.ps1 -Scopes @(
    # Read-only permissions
    'AuditLog.Read.All'
    'Directory.Read.All'
    'Organization.Read.All'
)
#endregion ---------------------------------------------------------------------

#region [COMMON] ENVIRONMENT ---------------------------------------------------
./Common_0002__Import-AzAutomationVariableToPSEnv.ps1 1> $null      # Implicitly connects to Azure Cloud
$Constants = ./CloudAdmin_0000__Common_0000__Get-ConfigurationConstants.ps1
./Common_0000__Convert-PSEnvToPSScriptVariable.ps1 -Variable $Constants 1> $null
#endregion ---------------------------------------------------------------------

#region Required Microsoft Entra Directory Permissions Validation --------------
$DirectoryPermissions = ./Common_0003__Confirm-MgDirectoryRoleActiveAssignment.ps1 -Roles @(
    # Read user sign-in activity logs
    Write-Verbose '[RequiredMicrosoftEntraDirectoryPermissionsValidation]: - Require directory role: Reports Reader, Directory Scope: /'
    @{
        DisplayName = 'Reports Reader'
        TemplateId  = '4a5d8f65-41da-4de4-8968-e035b65339cf'
    }
)
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

try {
    $VerifiedDomains = (./Common_0001__Invoke-MgGraphRequest.ps1 @{ Method = 'GET'; Uri = 'https://graph.microsoft.com/v1.0/organization'; OutputType = 'PSObject'; ErrorAction = 'Stop'; Verbose = $false; Debug = $false }).Value.VerifiedDomains
}
catch {
    Throw $_
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
                $refUserId = @(./Common_0003__Find-MgUserWithSoftDeleted.ps1 -UserId $LocalUserId[$_])[0].Id
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
                            NeverUsedDays                    = $NeverUsedDays
                            DisabledOnly                     = $DisabledOnly
                            EnabledOnly                      = $EnabledOnly
                            ExpandReferralUserId             = $ExpandReferralUserId
                            ReferralUserId                   = $refUserId
                            ReferralUserIdExtensionAttribute = $ReferenceExtensionAttribute
                        }
                        try {
                            [void] $return.AddRange(@(Get-CloudAdminAccountsByTier @params))
                        }
                        catch {
                            Throw $_
                        }
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
                NeverUsedDays                    = $NeverUsedDays
                DisabledOnly                     = $DisabledOnly
                EnabledOnly                      = $EnabledOnly
                ExpandReferralUserId             = $ExpandReferralUserId
                ReferralUserIdExtensionAttribute = $ReferenceExtensionAttribute
            }
            try {
                [void] $return.AddRange(@(Get-CloudAdminAccountsByTier @params))
            }
            catch {
                Throw $_
            }
        }
    }
}
Write-Verbose "[GetCloudAdminAccount]: - Found $($return.Count) dedicated cloud administrator accounts."
#endregion ---------------------------------------------------------------------

Get-Variable | Where-Object { $StartupVariables -notcontains $_.Name } | & { process { Remove-Variable -Scope 0 -Name $_.Name -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue -Verbose:$false -Debug:$false -Confirm:$false -WhatIf:$false } }        # Delete variables created in this script to free up memory for tiny Azure Automation sandbox
if ($PSCommandPath) { Write-Verbose "-----END of $((Get-Item $PSCommandPath).Name) ---" }

if ($OutJson) { if ($return.Count -eq 0) { return '[]' }; ./Common_0000__Write-JsonOutput.ps1 $return; return }

if ($OutCsv) {
    if ($return.Count -eq 0) { return }

    $properties = @{
        'lastSignInDateTime'                  = 'signInActivity.lastSignInDateTime'
        'lastNonInteractiveSignInDateTime'    = 'signInActivity.lastNonInteractiveSignInDateTime'
        'lastSuccessfulSignInDateTime'        = 'signInActivity.lastSuccessfulSignInDateTime'
        'extensionAttribute1'                 = 'onPremisesExtensionAttributes.extensionAttribute1'
        'extensionAttribute2'                 = 'onPremisesExtensionAttributes.extensionAttribute2'
        'extensionAttribute3'                 = 'onPremisesExtensionAttributes.extensionAttribute3'
        'extensionAttribute4'                 = 'onPremisesExtensionAttributes.extensionAttribute4'
        'extensionAttribute5'                 = 'onPremisesExtensionAttributes.extensionAttribute5'
        'extensionAttribute6'                 = 'onPremisesExtensionAttributes.extensionAttribute6'
        'extensionAttribute7'                 = 'onPremisesExtensionAttributes.extensionAttribute7'
        'extensionAttribute8'                 = 'onPremisesExtensionAttributes.extensionAttribute8'
        'extensionAttribute9'                 = 'onPremisesExtensionAttributes.extensionAttribute9'
        'extensionAttribute10'                = 'onPremisesExtensionAttributes.extensionAttribute10'
        'extensionAttribute11'                = 'onPremisesExtensionAttributes.extensionAttribute11'
        'extensionAttribute12'                = 'onPremisesExtensionAttributes.extensionAttribute12'
        'extensionAttribute13'                = 'onPremisesExtensionAttributes.extensionAttribute13'
        'extensionAttribute14'                = 'onPremisesExtensionAttributes.extensionAttribute14'
        'extensionAttribute15'                = 'onPremisesExtensionAttributes.extensionAttribute15'

        'refDisplayName'                      = 'referralUserAccount.displayName'
        'refUserPrincipalName'                = 'referralUserAccount.userPrincipalName'
        'refOnPremisesSamAccountName'         = 'referralUserAccount.onPremisesSamAccountName'
        'refId'                               = 'referralUserAccount.id'
        'refAccountEnabled'                   = 'referralUserAccount.accountEnabled'
        'refCreatedDateTime'                  = 'referralUserAccount.createdDateTime'
        'refDeletedDateTime'                  = 'referralUserAccount.deletedDateTime'
        'refMail'                             = 'referralUserAccount.mail'
        'refCompanyName'                      = 'referralUserAccount.companyName'
        'refDepartment'                       = 'referralUserAccount.department'
        'refStreetAddress'                    = 'referralUserAccount.streetAddress'
        'refCity'                             = 'referralUserAccount.city'
        'refPostalCode'                       = 'referralUserAccount.postalCode'
        'refState'                            = 'referralUserAccount.state'
        'refCountry'                          = 'referralUserAccount.country'
        'refLastSignInDateTime'               = 'referralUserAccount.signInActivity.lastSignInDateTime'
        'refLastNonInteractiveSignInDateTime' = 'referralUserAccount.signInActivity.lastNonInteractiveSignInDateTime'
        'refLastSuccessfulSignInDateTime'     = 'referralUserAccount.signInActivity.lastSuccessfulSignInDateTime'
        'refExtensionAttribute1'              = 'referralUserAccount.onPremisesExtensionAttributes.extensionAttribute1'
        'refExtensionAttribute2'              = 'referralUserAccount.onPremisesExtensionAttributes.extensionAttribute2'
        'refExtensionAttribute3'              = 'referralUserAccount.onPremisesExtensionAttributes.extensionAttribute3'
        'refExtensionAttribute4'              = 'referralUserAccount.onPremisesExtensionAttributes.extensionAttribute4'
        'refExtensionAttribute5'              = 'referralUserAccount.onPremisesExtensionAttributes.extensionAttribute5'
        'refExtensionAttribute6'              = 'referralUserAccount.onPremisesExtensionAttributes.extensionAttribute6'
        'refExtensionAttribute7'              = 'referralUserAccount.onPremisesExtensionAttributes.extensionAttribute7'
        'refExtensionAttribute8'              = 'referralUserAccount.onPremisesExtensionAttributes.extensionAttribute8'
        'refExtensionAttribute9'              = 'referralUserAccount.onPremisesExtensionAttributes.extensionAttribute9'
        'refExtensionAttribute10'             = 'referralUserAccount.onPremisesExtensionAttributes.extensionAttribute10'
        'refExtensionAttribute11'             = 'referralUserAccount.onPremisesExtensionAttributes.extensionAttribute11'
        'refExtensionAttribute12'             = 'referralUserAccount.onPremisesExtensionAttributes.extensionAttribute12'
        'refExtensionAttribute13'             = 'referralUserAccount.onPremisesExtensionAttributes.extensionAttribute13'
        'refExtensionAttribute14'             = 'referralUserAccount.onPremisesExtensionAttributes.extensionAttribute14'
        'refExtensionAttribute15'             = 'referralUserAccount.onPremisesExtensionAttributes.extensionAttribute15'

        'managerDisplayName'                  = 'referralUserAccount.manager.displayName'
        'managerUserPrincipalName'            = 'referralUserAccount.manager.userPrincipalName'
        'managerOnPremisesSamAccountName'     = 'referralUserAccount.manager.onPremisesSamAccountName'
        'managerId'                           = 'referralUserAccount.manager.id'
        'managerAccountEnabled'               = 'referralUserAccount.manager.accountEnabled'
        'managerMail'                         = 'referralUserAccount.manager.mail'
    }

    ./Common_0000__Write-CsvOutput.ps1 -InputObject (
        $return | & {
            process {
                foreach ($property in $properties.GetEnumerator()) {
                    $nestedPropertyPath = $property.Value -split '\.'
                    if ($nestedPropertyPath.count -eq 3) {
                        $_ | Add-Member -NotePropertyName $property.Key -NotePropertyValue $_.$($nestedPropertyPath[0]).$($nestedPropertyPath[1]).$($nestedPropertyPath[2])
                    }
                    elseif ($nestedPropertyPath.count -eq 2) {
                        $_ | Add-Member -NotePropertyName $property.Key -NotePropertyValue $_.$($nestedPropertyPath[0]).$($nestedPropertyPath[1])
                    }
                    else {
                        Throw "Invalid nested property path: $($property.Value)"
                    }
                }

                $_ | Select-Object -Property @(
                    'securityTierLevel'
                    'displayName'
                    'userPrincipalName'
                    'id'
                    'accountEnabled'
                    'createdDateTime'
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
                    'refCreatedDateTime'
                    'refDeletedDateTime'
                    'refMail'
                    'refCompanyName'
                    'refDepartment'
                    'refStreetAddress'
                    'refCity'
                    'refPostalCode'
                    'refState'
                    'refCountry'
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
                foreach ($property in $_.PSObject.Properties) {
                    if ($property.Value -is [DateTime]) {
                        $property.Value = [DateTime]::Parse($property.Value).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                    }
                    elseif ($property.Value -is [bool]) {
                        $property.Value = if ($property.Value) { '1' } else { '0' }
                    }
                    elseif ($property.Value -is [array]) {
                        $property.Value = $property.Value -join ', '
                    }
                }
                $_
            }
        }
    ) -StorageUri $(
        if (-not [string]::IsNullOrEmpty($StorageUri)) {
            $baseUri = ($uri = [System.Uri]$StorageUri).GetLeftPart([System.UriPartial]::Path)
            $baseUri + '/' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '_Get-CloudAdminAccountsByPrimaryAccount.csv' + $uri.Query
        }
    )
    return
}

if ($OutText) { if ($return.Count -eq 0) { return 'No cloud admin accounts found.' }; $return.userPrincipalName; return }

if ($return.Count -eq 0) {
    Write-Information 'No cloud admin accounts found.' -InformationAction Continue
}

return $return
