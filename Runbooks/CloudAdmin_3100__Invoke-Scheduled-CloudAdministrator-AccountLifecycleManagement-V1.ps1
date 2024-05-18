<#PSScriptInfo
.VERSION 0.0.1
.GUID ae957fef-f6c2-458d-bf37-27211dfd2640
.AUTHOR Julian Pawlowski
.COMPANYNAME Workoho GmbH
.COPYRIGHT © 2024 Workoho GmbH
.TAGS TieringModel CloudAdministrator Identity Microsoft365 Security Azure Automation AzureAutomation
.LICENSEURI https://github.com/workoho/Entra-Tiering-Security-Model/blob/main/LICENSE.txt
.PROJECTURI https://github.com/workoho/Entra-Tiering-Security-Model
.ICONURI
.EXTERNALMODULEDEPENDENCIES Microsoft.Graph,Microsoft.Graph.Beta,Az
.REQUIREDSCRIPTS CloudAdmin_0000__Common_0000__Get-ConfigurationConstants.ps1
.EXTERNALSCRIPTDEPENDENCIES https://github.com/workoho/AzAuto-Common-Runbook-FW
.RELEASENOTES
    Version 0.0.1 (2024-05-18)
    - under development
#>

<#
.SYNOPSIS
    Manage the lifecycle of dedicated Cloud Administrator accounts based on the Entra Tiering Security Model.

.DESCRIPTION
    This runbook manages the lifecycle of dedicated Cloud Administrator accounts based on the Entra Tiering Security Model.
    The runbook is designed to be scheduled and executed on a regular basis to ensure that the Cloud Administrator accounts are in sync with the referral accounts.

.PARAMETER ReferralUserId
    User account identifier of the existing primary user account. May be an Entra Identity Object ID or User Principal Name (UPN).
    External or guest accounts are converted to their local User Principal Name automatically.

.PARAMETER Tier
    The Tier level where the script is searching for the Cloud Administrator account. If left empty, the script will search for all Tiers.

.PARAMETER JobReference
    This information may be added for back reference in other IT systems. It will simply be added to the Job data.

.PARAMETER OutObject
    Output the result as object, e.g. when working with PowerShell pipelining.

.PARAMETER OutputJson
    Output the result in JSON format.
    This is useful when output data needs to be processed in other IT systems after the job was completed.

.PARAMETER OutText
    Output the cloud administrator account user principal name if the account was changed, deleted, or recovered.

.OUTPUTS
    Output may be requested by using one of the parameters -OutObject, -OutputJson, or -OutText.
    Otherwise, a Success text output is generated, indicating the success of the job.
#>

[CmdletBinding()]
Param (
    [Array]$ReferralUserId,
    [Array]$Tier,
    [Hashtable]$JobReference,
    [Boolean]$OutJson,
    [Boolean]$OutText,
    [Boolean]$OutObject
)

#region [COMMON] PARAMETER COUNT VALIDATION ------------------------------------
if (
    ($ReferralUserId.Count -gt 1) -and
    ($ReferralUserId.Count -ne $Tier.Count)
) {
    Throw 'ReferralUserId and Tier must contain the same number of items for batch processing.'
}
#endregion ---------------------------------------------------------------------

#region [COMMON] IMPORT MODULES ------------------------------------------------
./Common_0000__Import-Module.ps1 -Modules @(
    @{ Name = 'Microsoft.Graph.Users'; MinimumVersion = '2.0'; MaximumVersion = '2.65535' }
    @{ Name = 'Microsoft.Graph.Users.Actions'; MinimumVersion = '2.0'; MaximumVersion = '2.65535' }
) 1> $null
#endregion ---------------------------------------------------------------------

#region [COMMON] OPEN CONNECTIONS: Microsoft Graph -----------------------------
./Common_0001__Connect-MgGraph.ps1 -Scopes @(
    # Read-only permissions
    'Directory.Read.All'

    # Write permissions
    'User.ReadWrite.All'
)
#endregion ---------------------------------------------------------------------

#region [COMMON] ENVIRONMENT ---------------------------------------------------
./Common_0002__Import-AzAutomationVariableToPSEnv.ps1 1> $null      # Implicitly connects to Azure Cloud
$Constants = ./CloudAdmin_0000__Common_0000__Get-ConfigurationConstants.ps1
./Common_0000__Convert-PSEnvToPSScriptVariable.ps1 -Variable $Constants 1> $null
#endregion ---------------------------------------------------------------------

#region [COMMON] INITIALIZE RETURN VARIABLES -----------------------------------
$returnOutput = [System.Collections.ArrayList]::new()
$returnInformation = [System.Collections.ArrayList]::new()
$returnWarning = [System.Collections.ArrayList]::new()
$returnError = [System.Collections.ArrayList]::new()
#endregion ---------------------------------------------------------------------

#region [COMMON] CONCURRENT JOBS -----------------------------------------------
$concurrentJobsTimeoutError = $false
$ConcurrentJobsWaitStartTime = (Get-Date).ToUniversalTime()
if ((./Common_0002__Wait-AzAutomationConcurrentJob.ps1) -ne $true) {
    $concurrentJobsTimeoutError = $true
    [void] $script:returnError.Add(( ./Common_0000__Write-Error.ps1 @{
                Message           = "Maximum job runtime was reached."
                ErrorId           = '504'
                Category          = 'OperationTimeout'
                RecommendedAction = 'Try again later.'
                CategoryActivity  = 'Job Concurrency Check'
                CategoryReason    = "Maximum job runtime was reached."
            }))
}
$ConcurrentJobsWaitEndTime = (Get-Date).ToUniversalTime()
$ConcurrentJobsTime = $ConcurrentJobsWaitEndTime - $ConcurrentJobsWaitStartTime
#endregion ---------------------------------------------------------------------

#region Required Microsoft Entra Directory Permissions Validation --------------
# $AllowPrivilegedRoleAdministratorInAzureAutomation = $false
# $DirectoryPermissions = ./Common_0003__Confirm-MgDirectoryRoleActiveAssignment.ps1 -AllowPrivilegedRoleAdministratorInAzureAutomation:$AllowPrivilegedRoleAdministratorInAzureAutomation -Roles @(
#     if (
#         ([string]::IsNullOrEmpty($DedicatedAccount_Tier0)) -or
#         ($DedicatedAccount_Tier0 -ne 'None') -or
#         ([string]::IsNullOrEmpty($DedicatedAccount_Tier1)) -or
#         ($DedicatedAccount_Tier1 -ne 'None') -or
#         ([string]::IsNullOrEmpty($DedicatedAccount_Tier2)) -or
#         ($DedicatedAccount_Tier2 -ne 'None')
#     ) {
#         # Change existing Tier 0 Cloud Admin Accounts
#         if (
#             ([string]::IsNullOrEmpty($DedicatedAccount_Tier0)) -or
#             ($DedicatedAccount_Tier0 -ne 'None')
#         ) {
#             Write-Verbose "[RequiredMicrosoftEntraDirectoryPermissionsValidation]: - Require directory role (Tier 0): User Administrator, Directory Scope: $(if ($AccountRestrictedAdminUnitId_Tier0) { "/administrativeUnits/$AccountRestrictedAdminUnitId_Tier0" } else { '/' })"
#             @{
#                 DisplayName      = 'User Administrator'
#                 TemplateId       = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
#                 DirectoryScopeId = if ($AccountRestrictedAdminUnitId_Tier0) { "/administrativeUnits/$AccountRestrictedAdminUnitId_Tier0" } else { '/' }
#             }

#             # If for whatever reason one does not want/have group-based licensing, manual license assignment is required
#             if ([string]::IsNullOrEmpty($LicenseGroupId_Tier0)) {
#                 Write-Verbose "[RequiredMicrosoftEntraDirectoryPermissionsValidation]: - Require directory role (Tier 0): License Administrator, Directory Scope: $(if ($AccountRestrictedAdminUnitId_Tier0) { "/administrativeUnits/$AccountRestrictedAdminUnitId_Tier0" } else { '/' })"
#                 @{
#                     DisplayName      = 'License Administrator'
#                     TemplateId       = '4d6ac14f-3453-41d0-bef9-a3e0c569773a'
#                     DirectoryScopeId = if ($AccountRestrictedAdminUnitId_Tier0) { "/administrativeUnits/$AccountRestrictedAdminUnitId_Tier0" } else { '/' }
#                 }
#             }
#         }

#         # Change existing Tier 1 Cloud Admin Accounts
#         if (
#             ([string]::IsNullOrEmpty($DedicatedAccount_Tier1)) -or
#             ($DedicatedAccount_Tier1 -ne 'None')
#         ) {
#             Write-Verbose "[RequiredMicrosoftEntraDirectoryPermissionsValidation]: - Require directory role (Tier 1): User Administrator, Directory Scope: $(if ($AccountAdminUnitId_Tier1) { "/administrativeUnits/$AccountAdminUnitId_Tier1" } else { '/' })"
#             @{
#                 DisplayName      = 'User Administrator'
#                 TemplateId       = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
#                 DirectoryScopeId = if ($AccountAdminUnitId_Tier1) { "/administrativeUnits/$AccountAdminUnitId_Tier1" } else { '/' }
#             }

#             # If for whatever reason one does not want/have group-based licensing, manual license assignment is required
#             if ([string]::IsNullOrEmpty($LicenseGroupId_Tier1)) {
#                 Write-Verbose "[RequiredMicrosoftEntraDirectoryPermissionsValidation]: - Require directory role (Tier 1): License Administrator, Directory Scope: $(if ($AccountAdminUnitId_Tier1) { "/administrativeUnits/$AccountAdminUnitId_Tier1" } else { '/' })"
#                 @{
#                     DisplayName      = 'License Administrator'
#                     TemplateId       = '4d6ac14f-3453-41d0-bef9-a3e0c569773a'
#                     DirectoryScopeId = if ($AccountAdminUnitId_Tier1) { "/administrativeUnits/$AccountAdminUnitId_Tier1" } else { '/' }
#                 }
#             }
#         }

#         # Change existing Tier 2 Cloud Admin Accounts
#         if (
#             ([string]::IsNullOrEmpty($DedicatedAccount_Tier2)) -or
#             ($DedicatedAccount_Tier2 -ne 'None')
#         ) {
#             Write-Verbose "[RequiredMicrosoftEntraDirectoryPermissionsValidation]: - Require directory role (Tier 2): User Administrator, Directory Scope: $(if ($AccountAdminUnitId_Tier2) { "/administrativeUnits/$AccountAdminUnitId_Tier2" } else { '/' })"
#             @{
#                 DisplayName      = 'User Administrator'
#                 TemplateId       = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
#                 DirectoryScopeId = if ($AccountAdminUnitId_Tier2) { "/administrativeUnits/$AccountAdminUnitId_Tier2" } else { '/' }
#             }

#             # If for whatever reason one does not want/have group-based licensing, manual license assignment is required
#             if ([string]::IsNullOrEmpty($LicenseGroupId_Tier2)) {
#                 Write-Verbose "[RequiredMicrosoftEntraDirectoryPermissionsValidation]: - Require directory role (Tier 2): License Administrator, Directory Scope: $(if ($AccountAdminUnitId_Tier2) { "/administrativeUnits/$AccountAdminUnitId_Tier2" } else { '/' })"
#                 @{
#                     DisplayName      = 'License Administrator'
#                     TemplateId       = '4d6ac14f-3453-41d0-bef9-a3e0c569773a'
#                     DirectoryScopeId = if ($AccountAdminUnitId_Tier2) { "/administrativeUnits/$AccountAdminUnitId_Tier2" } else { '/' }
#                 }
#             }
#         }
#     }
# )
#endregion ---------------------------------------------------------------------

#region [COMMON] INITIALIZE SCRIPT VARIABLES -----------------------------------
$persistentError = $false
$Iteration = 0

$return = @{
    Job = ./Common_0003__Get-AzAutomationJobInfo.ps1
}
if ($JobReference) { $return.Job.Reference = $JobReference }
#endregion ---------------------------------------------------------------------

#region Find Admin Accounts ----------------------------------------------------
$accounts = [System.Collections.ArrayList]::new()
if ($ReferralUserId) {
    $tenant = Get-MgOrganization -OrganizationId (Get-MgContext).TenantId
    $tenantDomain = $tenant.VerifiedDomains | Where-Object { $_.IsInitial -eq $true }
    $LocalUserId = @( ./Common_0002__Convert-UserIdToLocalUserId.ps1 -UserId $ReferralUserId -VerifiedDomains $tenant.VerifiedDomains )
    if ($LocalUserId.Count -ne $ReferralUserId.Count) { Throw 'ReferralUserId count must not be different after LocalUserId conversion.' }

    0..$($ReferralUserId.Count - 1) | & {
        process {
            if (
                ($null -eq $ReferralUserId[$_]) -or
                ($ReferralUserId[$_] -isnot [string]) -or
                [string]::IsNullOrEmpty( $ReferralUserId[$_].Trim() )
            ) {
                Write-Verbose "[ProcessReferralUserLoop]: - ReferralUserId-$_ Type : $(($ReferralUserId[$_]).GetType().Name)"
                Write-Verbose "[ProcessReferralUserLoop]: - ReferralUserId-$_ Value: '$($ReferralUserId[$_])'"
                Write-Warning "[ProcessReferralUserLoop]: - Ignoring array item $_ because 'ReferralUserId' is not a string or IsNullOrEmpty"
                return
            }

            if (
                ($null -eq $LocalUserId[$_]) -or
                ($LocalUserId[$_] -isnot [string]) -or
                [string]::IsNullOrEmpty( $LocalUserId[$_].Trim() )
            ) {
                Write-Verbose "[ProcessReferralUserLoop]: - LocalUserId-$_ Type : $(($LocalUserId[$_]).GetType().Name)"
                Write-Verbose "[ProcessReferralUserLoop]: - LocalUserId-$_ Value: '$($LocalUserId[$_])'"
                Write-Warning "[ProcessReferralUserLoop]: - Ignoring array item $_ because 'LocalUserId' is not a string or IsNullOrEmpty"
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
                    Write-Error '[ProcessReferralUserLoop]: - Auto-converting of Tier string to Int32 failed'
                }
            }

            Write-Verbose "[ProcessReferralUserLoop]: - Processing ReferralUserId-${_}: $($ReferralUserId[$_])"
            try {
                $user = Get-MgUser -UserId $LocalUserId[$_] -ErrorAction Stop
            }
            catch {
                Write-Error "[ProcessReferralUserLoop]: - Get-MgUser failed for ReferralUserId-${_}: $($ReferralUserId[$_])"
                return
            }

            if (
                -not [string]::IsNullOrEmpty($AccountTypeExtensionAttributePrefix_Tier0) -and
                -not [string]::IsNullOrEmpty($ReferenceExtensionAttribute) -and
                (
                    $null -eq $Tier -or
                    [string]::IsNullOrEmpty( $Tier[$_] ) -or
                    $Tier[$_] -eq 0
                )
            ) {
                Write-Verbose "[ProcessReferralUserLoop]: - Processing Tier 0 accounts with extension attribute '$AccountTypeExtensionAttribute' and prefix '$AccountTypeExtensionAttributePrefix_Tier0'"
                $params = @{
                    All              = $true
                    ConsistencyLevel = 'eventual'
                    CountVariable    = 'CountVar'
                    Filter           = @(
                        "userType eq 'Member'"
                        "not endsWith(userPrincipalName, '#EXT#@$tenantDomain')"
                        "onPremisesSecurityIdentifier eq null"
                        "onPremisesExtensionAttributes/extensionAttribute$ReferenceExtensionAttribute eq '$($user.Id)'"
                        "startswith(onPremisesExtensionAttributes/extensionAttribute$AccountTypeExtensionAttribute, '$AccountTypeExtensionAttributePrefix_Tier0')"
                    ) -join ' and '
                    Select           = @(
                        'id'
                        'displayName'
                        'userPrincipalName'
                        'accountEnabled'
                        'mail'
                        'onPremisesExtensionAttributes'
                    )
                    ErrorAction      = 'Stop'
                }
                [void] $accounts.AddRange(@(Get-MgUser @params))
            }

            if (
                -not [string]::IsNullOrEmpty($AccountTypeExtensionAttributePrefix_Tier1) -and
                -not [string]::IsNullOrEmpty($ReferenceExtensionAttribute) -and
                (
                    $null -eq $Tier -or
                    [string]::IsNullOrEmpty( $Tier[$_] ) -or
                    $Tier[$_] -eq 1
                )
            ) {
                Write-Verbose "[ProcessReferralUserLoop]: - Processing Tier 1 accounts with extension attribute '$AccountTypeExtensionAttribute' and prefix '$AccountTypeExtensionAttributePrefix_Tier1'"
                $params = @{
                    All              = $true
                    ConsistencyLevel = 'eventual'
                    CountVariable    = 'CountVar'
                    Filter           = @(
                        "userType eq 'Member'"
                        "not endsWith(userPrincipalName, '#EXT#@$tenantDomain')"
                        "onPremisesSecurityIdentifier eq null"
                        "onPremisesExtensionAttributes/extensionAttribute$ReferenceExtensionAttribute eq '$($user.Id)'"
                        "startswith(onPremisesExtensionAttributes/extensionAttribute$AccountTypeExtensionAttribute, '$AccountTypeExtensionAttributePrefix_Tier1')"
                    ) -join ' and '
                    Select           = @(
                        'id'
                        'displayName'
                        'userPrincipalName'
                        'accountEnabled'
                        'mail'
                        'onPremisesExtensionAttributes'
                    )
                    ErrorAction      = 'Stop'
                }
                [void] $accounts.AddRange(@(Get-MgUser @params))
            }

            if (
                -not [string]::IsNullOrEmpty($AccountTypeExtensionAttributePrefix_Tier2) -and
                -not [string]::IsNullOrEmpty($ReferenceExtensionAttribute) -and
                (
                    $null -eq $Tier -or
                    [string]::IsNullOrEmpty( $Tier[$_] ) -or
                    $Tier[$_] -eq 2
                )
            ) {
                Write-Verbose "[ProcessReferralUserLoop]: - Processing Tier 1 accounts with extension attribute '$AccountTypeExtensionAttribute' and prefix '$AccountTypeExtensionAttributePrefix_Tier2'"
                $params = @{
                    All              = $true
                    ConsistencyLevel = 'eventual'
                    CountVariable    = 'CountVar'
                    Filter           = @(
                        "userType eq 'Member'"
                        "not endsWith(userPrincipalName, '#EXT#@$tenantDomain')"
                        "onPremisesSecurityIdentifier eq null"
                        "onPremisesExtensionAttributes/extensionAttribute$ReferenceExtensionAttribute eq '$($user.Id)'"
                        "startswith(onPremisesExtensionAttributes/extensionAttribute$AccountTypeExtensionAttribute, '$AccountTypeExtensionAttributePrefix_Tier2')"
                    ) -join ' and '
                    Select           = @(
                        'id'
                        'displayName'
                        'userPrincipalName'
                        'accountEnabled'
                        'mail'
                        'onPremisesExtensionAttributes'
                    )
                    ErrorAction      = 'Stop'
                }
                [void] $accounts.AddRange(@(Get-MgUser @params))
            }
        }
    }
}
else {
    if ([string]::IsNullOrEmpty($AccountTypeExtensionAttribute)) {
        Throw 'AccountTypeExtensionAttribute must not be null or empty.'
    }
    if (-not [string]::IsNullOrEmpty($AccountTypeExtensionAttributePrefix_Tier0)) {
        Write-Verbose "[FindAdminAccountT0]: - Processing Tier 0 accounts with extension attribute '$AccountTypeExtensionAttribute' and prefix '$AccountTypeExtensionAttributePrefix_Tier0'"
        $params = @{
            All              = $true
            ConsistencyLevel = 'eventual'
            CountVariable    = 'CountVar'
            Filter           = @(
                "userType eq 'Member'"
                "not endsWith(userPrincipalName, '#EXT#@$tenantDomain')"
                "onPremisesSecurityIdentifier eq null"
                "startswith(onPremisesExtensionAttributes/extensionAttribute$AccountTypeExtensionAttribute, '$AccountTypeExtensionAttributePrefix_Tier0')"
            ) -join ' and '
            Select           = @(
                'id'
                'displayName'
                'userPrincipalName'
                'accountEnabled'
                'mail'
                'onPremisesExtensionAttributes'
            )
            ErrorAction      = 'Stop'
        }
        [void] $accounts.AddRange(@(Get-MgUser @params))
    }

    if (-not [string]::IsNullOrEmpty($AccountTypeExtensionAttributePrefix_Tier1)) {
        Write-Verbose "[FindAdminAccountT1]: - Processing Tier 1 accounts with extension attribute '$AccountTypeExtensionAttribute' and prefix '$AccountTypeExtensionAttributePrefix_Tier1'"
        $params = @{
            All              = $true
            ConsistencyLevel = 'eventual'
            CountVariable    = 'CountVar'
            Filter           = @(
                "userType eq 'Member'"
                "not endsWith(userPrincipalName, '#EXT#@$tenantDomain')"
                "onPremisesSecurityIdentifier eq null"
                "startswith(onPremisesExtensionAttributes/extensionAttribute$AccountTypeExtensionAttribute, '$AccountTypeExtensionAttributePrefix_Tier1')"
            ) -join ' and '
            Select           = @(
                'id'
                'displayName'
                'userPrincipalName'
                'accountEnabled'
                'mail'
                'onPremisesExtensionAttributes'
            )
            ErrorAction      = 'Stop'
        }
        [void] $accounts.AddRange(@(Get-MgUser @params))
    }

    if (-not [string]::IsNullOrEmpty($AccountTypeExtensionAttributePrefix_Tier2)) {
        Write-Verbose "[FindAdminAccountT2]: - Processing Tier 2 accounts with extension attribute '$AccountTypeExtensionAttribute' and prefix '$AccountTypeExtensionAttributePrefix_Tier2'"
        $params = @{
            All              = $true
            ConsistencyLevel = 'eventual'
            CountVariable    = 'CountVar'
            Filter           = @(
                "userType eq 'Member'"
                "not endsWith(userPrincipalName, '#EXT#@$tenantDomain')"
                "onPremisesSecurityIdentifier eq null"
                "startswith(onPremisesExtensionAttributes/extensionAttribute$AccountTypeExtensionAttribute, '$AccountTypeExtensionAttributePrefix_Tier2')"
            ) -join ' and '
            Select           = @(
                'id'
                'displayName'
                'userPrincipalName'
                'accountEnabled'
                'mail'
                'onPremisesExtensionAttributes'
            )
            ErrorAction      = 'Stop'
        }
        [void] $accounts.AddRange(@(Get-MgUser @params))
    }
}
Write-Verbose "[FindAdminAccount]: - Found $($accounts.Count) admin accounts"
#endregion ---------------------------------------------------------------------

#region Sync admin account status with referral account ------------------------
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

$accounts | & {
    process {
        Write-Verbose "[SyncAdminAccountStatus]: - Processing account: $($_.userPrincipalName) ($($_.Id))"
        if (
            [string]::IsNullOrEmpty( $_.OnPremisesExtensionAttributes."ExtensionAttribute$ReferenceExtensionAttribute" ) -or
            ($_.OnPremisesExtensionAttributes."ExtensionAttribute$ReferenceExtensionAttribute").Trim() -notmatch '^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$'
        ) {
            [void] $returnError.Add(( ./Common_0000__Write-Error.ps1 @{
                        Message           = "Account $($_.userPrincipalName) ($($_.Id)) does not have a valid reference value in OnPremisesExtensionAttributes.ExtensionAttribute$ReferenceExtensionAttribute."
                        ErrorId           = '400'
                        Category          = 'InvalidData'
                        RecommendedAction = 'Check the account and its reference value.'
                        CategoryActivity  = 'Account Status Sync'
                        CategoryReason    = "Account $($_.userPrincipalName) ($($_.Id)) does not have a valid reference value in OnPremisesExtensionAttributes.ExtensionAttribute$ReferenceExtensionAttribute."
                    }))
            return
        }

        if (
            [string]::IsNullOrEmpty( $_.OnPremisesExtensionAttributes."ExtensionAttribute$AccountTypeExtensionAttribute" ) -or
            (
                ($_.OnPremisesExtensionAttributes."ExtensionAttribute$AccountTypeExtensionAttribute").Trim() -notmatch "^$($AccountTypeExtensionAttributePrefix_Tier0).*" -and
                ($_.OnPremisesExtensionAttributes."ExtensionAttribute$AccountTypeExtensionAttribute").Trim() -notmatch "^$($AccountTypeExtensionAttributePrefix_Tier1).*" -and
                ($_.OnPremisesExtensionAttributes."ExtensionAttribute$AccountTypeExtensionAttribute").Trim() -notmatch "^$($AccountTypeExtensionAttributePrefix_Tier2).*"
            )
        ) {
            [void] $returnError.Add(( ./Common_0000__Write-Error.ps1 @{
                        Message           = "Account $($_.userPrincipalName) ($($_.Id)) does not have a valid account type value in OnPremisesExtensionAttributes.ExtensionAttribute$AccountTypeExtensionAttribute."
                        ErrorId           = '400'
                        Category          = 'InvalidData'
                        RecommendedAction = 'Check the account and its account type value.'
                        CategoryActivity  = 'Account Status Sync'
                        CategoryReason    = "Account $($_.userPrincipalName) ($($_.Id)) does not have a valid account type value in OnPremisesExtensionAttributes.ExtensionAttribute$AccountTypeExtensionAttribute."
                    }))
            return
        }

        $params = @{
            UserId         = ($_.OnPremisesExtensionAttributes."ExtensionAttribute$ReferenceExtensionAttribute").Trim()
            Select         = @(
                'id'
                'displayName'
                'userPrincipalName'
                'accountEnabled'
                'mail'
                'onPremisesExtensionAttributes'
            )
            ExpandProperty = 'manager'
            ErrorAction    = 'SilentlyContinue'
        }
        $refUserObj = Get-MgUser @params
        $data = @{
            Input             = @{}
            Manager           = @{}
            Id                = $_.Id
            UserPrincipalName = $_.UserPrincipalName
            DisplayName       = $_.DisplayName
            AccountEnabled    = $_.AccountEnabled
            Mail              = $_.Mail
        }

        if ($null -eq $refUserObj) {
            Write-Verbose "[SyncAdminAccountStatus]: - Reference account not found for account: $($_.userPrincipalName) ($($_.Id))"
            Remove-MgUser -UserId $_.Id -ErrorAction Stop -WhatIf
            $data.deletedDateTime = (Get-Date).ToUniversalTime()
            Write-Verbose "[SyncAdminAccountStatus]: - Deleted account: $($data.userPrincipalName) ($($data.Id))"
            $returnOutput.Add($data)

            if ($OutText) {
                Write-Output $(if ($data.UserPrincipalName) { $data.UserPrincipalName } else { $null })
            }
            return
        }

        Write-Verbose "[SyncAdminAccountStatus]: - $($_.userPrincipalName) - Found reference account: $($refUserObj.UserPrincipalName) ($($refUserObj.Id))"

        $data.Input = @{
            ReferralUser = @{
                Id                = $refUserObj.Id
                UserPrincipalName = $refUserObj.UserPrincipalName
                Mail              = $refUserObj.Mail
                DisplayName       = $refUserObj.DisplayName
                AccountEnabled    = $refUserObj.AccountEnabled
            }
            Tier         = $null
        }
        if ($null -ne $refUserObj.Manager) {
            $data.Manager = @{
                Id                = $refUserObj.Manager.Id
                UserPrincipalName = $refUserObj.manager.AdditionalProperties.userPrincipalName
                Mail              = $refUserObj.manager.AdditionalProperties.mail
                DisplayName       = $refUserObj.manager.AdditionalProperties.displayName
            }
        }

        if ($_.AccountEnabled -ne $refUserObj.AccountEnabled) {
            Write-Verbose "[SyncAdminAccountStatus]: - $($_.userPrincipalName) - Change property AccountEnabled to '$($refUserObj.AccountEnabled)'"
            $data.AccountEnabled = $refUserObj.AccountEnabled
            Update-MgUser -UserId $_.Id -AccountEnabled $refUserObj.AccountEnabled -ErrorAction Stop -WhatIf
            $data.AccountEnabled = $refUserObj.AccountEnabled
            $returnOutput.Add($data)

            if ($OutText) {
                Write-Output $(if ($data.UserPrincipalName) { $data.UserPrincipalName } else { $null })
            }
        } else {
            Write-Verbose "[SyncAdminAccountStatus]: - $($_.userPrincipalName) - Property 'AccountEnabled' is in sync with reference account."
        }
    }
}
#endregion ---------------------------------------------------------------------

#region Output Return Data -----------------------------------------------------
$return.Output = $returnOutput
$return.Information = $returnInformation
$return.Warning = $returnWarning
$return.Error = $returnError
if ($returnError.Count -eq 0) { $return.Success = $true } else { $return.Success = $false }
$return.Job.EndTime = (Get-Date).ToUniversalTime()
$return.Job.Runtime = $return.Job.EndTime - $return.Job.StartTime
$return.Job.Waittime = $return.Job.StartTime - $return.Job.CreationTime

Write-Verbose "Total Waittime: $([math]::Floor($return.Job.Waittime.TotalSeconds)) sec ($([math]::Round($return.Job.Waittime.TotalMinutes, 1)) min)"
Write-Verbose "Total ConcurrentJobsTime: $([math]::Floor($return.Job.ConcurrentJobsTime.TotalSeconds)) sec ($([math]::Round($return.Job.ConcurrentJobsTime.TotalMinutes, 1)) min)"
Write-Verbose "Total Runtime: $([math]::Floor($return.Job.Runtime.TotalSeconds)) sec ($([math]::Round($return.Job.Runtime.TotalMinutes, 1)) min)"

if ($Webhook) { ./Common_0000__Submit-Webhook.ps1 -Uri $Webhook -Body $return 1> $null }

if (
    ($OutText -eq $true) -or
    (($PSBoundParameters.Keys -contains 'OutJson') -and ($OutJson -eq $false)) -or
    (($PSBoundParameters.Keys -contains 'OutObject') -and ($OutObject -eq $false))
) {
    if ($concurrentJobsTimeoutError) { Throw 'Concurrent jobs timeout error detected. Please try again later.' }
    return
}

if ($OutJson) { ./Common_0000__Write-JsonOutput.ps1 $return; if ($concurrentJobsTimeoutError) { Throw 'Concurrent jobs timeout error detected. Please try again later.' }; return }
if ($OutObject -eq $true) { if ($concurrentJobsTimeoutError) { Throw 'Concurrent jobs timeout error detected. Please try again later.' }; return $return }
if ($VerbosePreference -ne 'Continue') { Write-Output "Success = $($return.Success)" }
if ($concurrentJobsTimeoutError) { Throw 'Concurrent jobs timeout error detected. Please try again later.' }
#endregion ---------------------------------------------------------------------
