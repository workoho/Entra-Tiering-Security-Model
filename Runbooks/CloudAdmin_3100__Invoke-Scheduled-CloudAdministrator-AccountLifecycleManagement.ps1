<#PSScriptInfo
.VERSION 1.1.1
.GUID ae957fef-f6c2-458d-bf37-27211dfd2640
.AUTHOR Julian Pawlowski
.COMPANYNAME Workoho GmbH
.COPYRIGHT © 2024 Workoho GmbH
.TAGS TieringModel CloudAdministrator Identity Microsoft365 Security Azure Automation AzureAutomation
.LICENSEURI https://github.com/workoho/Entra-Tiering-Security-Model/blob/main/LICENSE.txt
.PROJECTURI https://github.com/workoho/Entra-Tiering-Security-Model
.ICONURI
.EXTERNALMODULEDEPENDENCIES Microsoft.Graph,Microsoft.Graph.Beta,Az
.REQUIREDSCRIPTS CloudAdmin_0000__Common_0000__Get-ConfigurationConstants.ps1,CloudAdmin_0000__Common_0001__Get-CloudAdminAccountsByPrimaryAccount.ps1
.EXTERNALSCRIPTDEPENDENCIES https://github.com/workoho/AzAuto-Common-Runbook-FW
.RELEASENOTES
    Version 1.1.1 (2024-06-18)
    - Fixed handling of accounts with missing referral accounts.
    - Fixed conflict between deletion and restore actions.
#>

<#
.SYNOPSIS
    Manage the lifecycle of dedicated Cloud Administrator accounts based on the Entra Tiering Security Model.

.DESCRIPTION
    This runbook manages the lifecycle of dedicated Cloud Administrator accounts based on the Entra Tiering Security Model.
    The runbook is designed to be scheduled and executed on a regular basis to ensure that the Cloud Administrator accounts are in sync with the primary user accounts.

    The runbook performs the following actions:
    - Soft-deletes Cloud Administrator accounts that have a soft-deleted associated primary user account, or whose object ID cannot be found anymore.
    - Restores Cloud Administrator accounts that have been soft-deleted and have an associated primary user account that is NOT soft-deleted.
    - Disables Cloud Administrator accounts that have an associated primary user account that is disabled.
    - Re-enables Cloud Administrator accounts that have been disabled and have an associated primary user account that is enabled.

    The runbook can be executed in the following modes:
    - Single mode: The runbook processes a single Cloud Administrator account.
    - Batch mode: The runbook processes multiple Cloud Administrator accounts in a single run.

    Please note that special procedures might be required for early deletion of Cloud Administrator accounts, for example, for cloud admin accounts that are no longer needed, but the primary user account is still active.
    In such cases, the Cloud Administrator account must be permanently deleted from Microsoft Entra, including to remove the account from the Entra ID recycle bin. Otherwise, the cloud admin account will be restored automatically.
    Alternatively, you may set the 'LifecycleRestoreAfterDelete_Tier0', 'LifecycleRestoreAfterDelete_Tier1', or 'LifecycleRestoreAfterDelete_Tier2' variable to false to prevent automatic restoration of the cloud admin account.

    PLease note that for security reasons, it is highly recommended to keep the automatic restoration of Cloud Administrator accounts disabled. Once a Cloud Administrator account is deleted, it should not be restored anymore and better be re-created with blank permission history if needed.
    This is to prevent any hidden security risks that may arise from the restoration of prior permissions and access rights that might not be needed anymore, or that might have been granted to unauthorized users.
    You may decide to restore a Cloud Administrator account manually if needed, but this should be a conscious decision and not an automatic process.

    To control automatic lifecycle management, the runbook uses the following Azure Automation variables for configuration:
    - LifecycleDelete_Tier0, LifecycleDelete_Tier1, LifecycleDelete_Tier2: Specifies whether to automatically soft-delete Cloud Administrator accounts that have no associated primary user account. Default is false.
    - LifecycleRestoreAfterDelete_Tier0, LifecycleRestoreAfterDelete_Tier1, LifecycleRestoreAfterDelete_Tier2: Specifies whether to automatically restore Cloud Administrator accounts that have been soft-deleted and have an associated primary user account. Default is false.
    - LifecycleDisable_Tier0, LifecycleDisable_Tier1, LifecycleDisable_Tier2: Specifies whether to automatically disable Cloud Administrator accounts that have a disabled associated primary user account. Default is false.
    - LifecycleEnableAfterDisable_Tier0, LifecycleEnableAfterDisable_Tier1, LifecycleEnableAfterDisable_Tier2: Specifies whether to automatically enable Cloud Administrator accounts that have been disabled and have an enabled associated primary user account. Default is false.

    In any case, the runbook will log an action plan in the 'accountLifecycle' property of the output object.
    If the action is not performed by the runbook, the status will be set to 'ToBe<action>' and you may follow up manually.

    Using the -OutCsv parameter, the runbook can store the output in an Azure Blob Storage container or Azure File Share. That way, you can keep a record of the lifecycle management actions performed by the runbook.
    The CSV file can be used for auditing purposes or to track the lifecycle management of Cloud Administrator accounts over time.
    You may also decide to use the runbook for reporting purposes only and use the CSV file to manually perform the lifecycle management actions as needed.

.PARAMETER ReferralUserId
    Specifies the object ID of the primary user account to search for all associated cloud admin accounts.
    May be an array, or a comma-separated string of object IDs or user principal names.
    If not provided, the script will retrieve all cloud admin accounts.

.PARAMETER Tier
    Specifies the security tier level of the cloud admin accounts to get. Must be a value between 0 and 2.
    If not provided, the script will search for all tiers.

    May be an array, or a comma-separated string of security tier levels.

.PARAMETER OutJson
    Specifies whether to output the result as JSON.

.PARAMETER OutCsv
    Specifies whether to output the result as CSV.
    The 'referralUserAccount' property will be expanded to include additional properties related to the primary user account.
    Also, the 'signInActivity' and 'accountLifecycle' properties are expanded into separate columns.

    If the AV_CloudAdmin_StorageUri variable is set in the Azure Automation account, the CSV file is stored in the specified Azure Blob Storage container or Azure File Share.
    The file name is prefixed with the current date and time in the format 'yyyyMMddTHHmmssfffZ'.
    Note that the managed identity of the Azure Automation account must have the necessary permissions to write to the specified storage account.
    That is, the managed identity must have the 'Storage Blob Data Contributor' role for a blob container or the 'Storage File Data SMB Share Contributor' role for a file share.
    Remember that general roles like 'Owner' or 'Contributor' do not grant write access to storage accounts.

.PARAMETER OutText
    Specifies whether to output the result as text.
    This will only output the user principal name of the cloud admin accounts with action.

.OUTPUTS
    Output may be requested in JSON, CSV, or text format by using one of the parameters -OutJson, -OutCsv, or -OutText.
    The output includes properties such as 'userPrincipalName', 'accountEnabled', 'deletedDateTime', 'lifecycleAction', 'lifecycleActionReason', 'lifecycleStatus', etc.

    If none of these parameters are used, the script returns an object array where each object represents a cloud admin account.
    and its associated primary user account in the 'referralUserAccount' property.
#>

[CmdletBinding()]
Param (
    [Array]$ReferralUserId,
    [Array]$Tier,
    [Boolean]$OutJson,
    [Boolean]$OutCsv,
    [Boolean]$OutText
)

#region [COMMON] PARAMETER COUNT VALIDATION ------------------------------------
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
                    Throw "[InvokeCloudAdministratorAccountLifecycleManagement]: - Auto-converting of Tier string to Int32 failed: $_"
                }
            }
        }
    }
}

if (
    ($ReferralUserId.Count -gt 1) -and
    ($ReferralUserId.Count -ne $Tier.Count)
) {
    Throw 'ReferralUserId and Tier must contain the same number of items for batch processing.'
}
#endregion ---------------------------------------------------------------------

#region [COMMON] OPEN CONNECTIONS: Microsoft Graph -----------------------------
./Common_0001__Connect-MgGraph.ps1 -Scopes @(
    # Read-only permissions
    'AuditLog.Read.All'
    'Directory.Read.All'
    'Organization.Read.All'

    # Write permissions
    'User.ReadWrite.All'
    'Directory.Write.Restricted'
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

$LifecycleDelete = @{
    0 = $LifecycleDelete_Tier0
    1 = $LifecycleDelete_Tier1
    2 = $LifecycleDelete_Tier2
}
$LifecycleRestoreAfterDelete = @{
    0 = $LifecycleRestoreAfterDelete_Tier0
    1 = $LifecycleRestoreAfterDelete_Tier1
    2 = $LifecycleRestoreAfterDelete_Tier2
}
$LifecycleDisable = @{
    0 = $LifecycleDisable_Tier0
    1 = $LifecycleDisable_Tier1
    2 = $LifecycleDisable_Tier2
}
$LifecycleEnableAfterDisable = @{
    0 = $LifecycleEnableAfterDisable_Tier0
    1 = $LifecycleEnableAfterDisable_Tier1
    2 = $LifecycleEnableAfterDisable_Tier2
}
#endregion ---------------------------------------------------------------------

#region [COMMON] CONCURRENT JOBS -----------------------------------------------
$concurrentJobsTimeoutError = $false
$ConcurrentJobsWaitStartTime = [DateTime]::UtcNow
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
$ConcurrentJobsWaitEndTime = [DateTime]::UtcNow
$ConcurrentJobsTime = $ConcurrentJobsWaitEndTime - $ConcurrentJobsWaitStartTime
#endregion ---------------------------------------------------------------------

#region Required Microsoft Entra Directory Permissions Validation --------------
$AllowPrivilegedRoleAdministratorInAzureAutomation = $false
$DirectoryPermissions = ./Common_0003__Confirm-MgDirectoryRoleActiveAssignment.ps1 -AllowPrivilegedRoleAdministratorInAzureAutomation:$AllowPrivilegedRoleAdministratorInAzureAutomation -Roles @(
    # Read user sign-in activity logs
    Write-Verbose '[RequiredMicrosoftEntraDirectoryPermissionsValidation]: - Require directory role: Reports Reader, Directory Scope: /'
    @{
        DisplayName = 'Reports Reader'
        TemplateId  = '4a5d8f65-41da-4de4-8968-e035b65339cf'
    }

    # Recover Cloud Admin Accounts
    Write-Verbose "[RequiredMicrosoftEntraDirectoryPermissionsValidation]: - Require directory role: User Administrator, Directory Scope: /"
    @{
        DisplayName      = 'User Administrator'
        TemplateId       = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
        DirectoryScopeId = '/'
    }
    @{
        DisplayName      = 'Privileged Authentication Administrator'
        TemplateId       = '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'
        DirectoryScopeId = '/'
        Justification    = 'Perform sensitive actions: https://learn.microsoft.com/en-us/graph/api/resources/users?view=graph-rest-1.0#who-can-perform-sensitive-actions'
    }

    # Change existing Tier 0 Cloud Admin Accounts
    Write-Verbose "[RequiredMicrosoftEntraDirectoryPermissionsValidation]: - Require directory role (Tier 0): User Administrator, Directory Scope: $(if ($AccountRestrictedAdminUnitId_Tier0) { "/administrativeUnits/$AccountRestrictedAdminUnitId_Tier0" } else { '/' })"
    @{
        DisplayName      = 'User Administrator'
        TemplateId       = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
        DirectoryScopeId = if ($AccountRestrictedAdminUnitId_Tier0) { "/administrativeUnits/$AccountRestrictedAdminUnitId_Tier0" } else { '/' }
    }
    @{
        DisplayName      = 'Privileged Authentication Administrator'
        TemplateId       = '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'
        DirectoryScopeId = if ($AccountRestrictedAdminUnitId_Tier0) { "/administrativeUnits/$AccountRestrictedAdminUnitId_Tier0" } else { '/' }
        Justification    = 'Perform sensitive actions: https://learn.microsoft.com/en-us/graph/api/resources/users?view=graph-rest-1.0#who-can-perform-sensitive-actions'
    }

    # Change existing Tier 1 Cloud Admin Accounts
    Write-Verbose "[RequiredMicrosoftEntraDirectoryPermissionsValidation]: - Require directory role (Tier 1): User Administrator, Directory Scope: $(if ($AccountAdminUnitId_Tier1) { "/administrativeUnits/$AccountAdminUnitId_Tier1" } else { '/' })"
    @{
        DisplayName      = 'User Administrator'
        TemplateId       = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
        DirectoryScopeId = if ($AccountAdminUnitId_Tier1) { "/administrativeUnits/$AccountAdminUnitId_Tier1" } else { '/' }
    }
    @{
        DisplayName      = 'Privileged Authentication Administrator'
        TemplateId       = '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'
        DirectoryScopeId = if ($AccountRestrictedAdminUnitId_Tier1) { "/administrativeUnits/$AccountRestrictedAdminUnitId_Tier1" } else { '/' }
        Justification    = 'Perform sensitive actions: https://learn.microsoft.com/en-us/graph/api/resources/users?view=graph-rest-1.0#who-can-perform-sensitive-actions'
    }

    # Change existing Tier 2 Cloud Admin Accounts
    Write-Verbose "[RequiredMicrosoftEntraDirectoryPermissionsValidation]: - Require directory role (Tier 2): User Administrator, Directory Scope: $(if ($AccountAdminUnitId_Tier2) { "/administrativeUnits/$AccountAdminUnitId_Tier2" } else { '/' })"
    @{
        DisplayName      = 'User Administrator'
        TemplateId       = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
        DirectoryScopeId = if ($AccountAdminUnitId_Tier2) { "/administrativeUnits/$AccountAdminUnitId_Tier2" } else { '/' }
    }
    @{
        DisplayName      = 'Privileged Authentication Administrator'
        TemplateId       = '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'
        DirectoryScopeId = if ($AccountRestrictedAdminUnitId_Tier2) { "/administrativeUnits/$AccountRestrictedAdminUnitId_Tier2" } else { '/' }
        Justification    = 'Perform sensitive actions: https://learn.microsoft.com/en-us/graph/api/resources/users?view=graph-rest-1.0#who-can-perform-sensitive-actions'
    }
)
#endregion ---------------------------------------------------------------------

#region [COMMON] INITIALIZE SCRIPT VARIABLES -----------------------------------
$return = @{
    Job = ./Common_0002__Get-AzAutomationJobInfo.ps1
}
#endregion ---------------------------------------------------------------------

#region Perform lifecycle management to cloud admin accounts -------------------
./CloudAdmin_0000__Common_0001__Get-CloudAdminAccountsByPrimaryAccount.ps1 -ReferralUserId $ReferralUserId -Tier $Tier -ExpandReferralUserId $true -ErrorAction Stop | & {
    process {
        if ($null -eq $_.securityTierLevel -or [string]::IsNullOrEmpty($_.securityTierLevel)) {
            Write-Warning "$($_.userPrincipalName) ($($_.Id)): - Account has no security tier level. Skipping."
            return
        }

        Write-Verbose "[SyncAdminAccountStatus]: - Processing account: $($_.userPrincipalName) ($($_.Id)) with security tier level $($_.securityTierLevel)"

        #region Delete account
        if (
            $null -eq $_.referralUserAccount -or
            [string]::IsNullOrEmpty($_.referralUserAccount.id)
        ) {
            if ($null -ne $_.deletedDateTime) {
                Write-Warning "$($_.userPrincipalName) ($($_.Id)): - Account has no existing referral account. Waiting for Microsoft Entra 30 days retention period to expire."
                $_ | Add-Member -MemberType NoteProperty -Name "accountLifecycle" -Value @{
                    action       = 'None'
                    actionReason = 'MissingReferralAccount'
                    status       = 'WaitForRetentionPeriod'
                }
            }
            elseif ($LifecycleDelete[$_.securityTierLevel] -eq $true) {
                Write-Verbose "[SyncAdminAccountStatus]: - Account has no existing referral account. Attempting to soft-delete account."
                $params = @{
                    Method      = 'DELETE'
                    Uri         = "/v1.0/users/$($_.Id)"
                    ErrorAction = 'Stop'
                    Verbose     = $false
                    Debug       = $false
                }
                try {
                    $null = ./Common_0000__Invoke-MgGraphRequest.ps1 $params
                }
                catch {
                    [void] $returnError.Add(( ./Common_0000__Write-Error.ps1 @{
                                Message           = "Failed to delete account $($_.userPrincipalName) ($($_.Id))."
                                ErrorId           = '500'
                                Category          = 'InvalidOperation'
                                RecommendedAction = 'Check the account and its referral account.'
                                CategoryActivity  = 'Account Status Sync'
                                CategoryReason    = "Failed to delete account $($_.userPrincipalName) ($($_.Id))."
                            }))
                    return
                }

                Write-Warning "$($_.userPrincipalName) ($($_.Id)): - Soft-Deleted account due to missing referral account."
                $_ | Add-Member -MemberType NoteProperty -Name "accountLifecycle" -Value @{
                    action       = 'SoftDelete'
                    actionReason = 'MissingReferralAccount'
                    status       = 'SoftDeleted'
                }
                $_.deletedDateTime = [DateTime]::UtcNow
            }
            else {
                Write-Warning "$($_.userPrincipalName) ($($_.Id)): - Account has no existing referral account and should be deleted, but no automatic deletion is performed."
                $_ | Add-Member -MemberType NoteProperty -Name "accountLifecycle" -Value @{
                    action       = 'DeferredSoftDelete'
                    actionReason = 'MissingReferralAccount'
                    status       = 'ToBeSoftDeleted'
                }
            }
        }
        elseif ($_.referralUserAccount.deletedDateTime) {
            if ($null -ne $_.deletedDateTime) {
                Write-Debug "[SyncAdminAccountStatus]: - Account is already soft-deleted. Skipping."
                return
            }
            elseif ($LifecycleDelete[$_.securityTierLevel] -eq $true) {
                Write-Verbose "[SyncAdminAccountStatus]: - Account should be soft-deleted to match referral account status. Attempting to soft-delete account."
                try {
                    $null = ./Common_0000__Invoke-MgGraphRequest.ps1 $params
                }
                catch {
                    [void] $returnError.Add(( ./Common_0000__Write-Error.ps1 @{
                                Message           = "Failed to delete account $($_.userPrincipalName) ($($_.Id))."
                                ErrorId           = '500'
                                Category          = 'InvalidOperation'
                                RecommendedAction = 'Check the account and its referral account.'
                                CategoryActivity  = 'Account Status Sync'
                                CategoryReason    = "Failed to delete account $($_.userPrincipalName) ($($_.Id))."
                            }))
                    return
                }

                Write-Warning "$($_.userPrincipalName) ($($_.Id)): - Soft-Deleted account due to soft-deleted referral account."
                $_ | Add-Member -MemberType NoteProperty -Name "accountLifecycle" -Value @{
                    Action = 'SoftDelete'
                    Status = 'SoftDeleted'
                    Reason = 'SoftDeletedReferralAccount'
                }
                $_.deletedDateTime = [DateTime]::UtcNow
            }
            else {
                Write-Warning "$($_.userPrincipalName) ($($_.Id)): - Account has no existing referral account and should be soft-deleted, but no automatic soft-deletion is performed."
                $_ | Add-Member -MemberType NoteProperty -Name "accountLifecycle" -Value @{
                    action       = 'DeferredSoftDelete'
                    actionReason = 'SoftDeletedReferralAccount'
                    status       = 'ToBeSoftDeleted'
                }
            }
        }
        #endregion

        #region Restore account
        elseif ($null -eq $_.deletedDateTime) {
            Write-Debug "[SyncAdminAccountStatus]: - Account does not need to be restored. Skipping."
        }
        elseif ($LifecycleRestoreAfterDelete[$_.securityTierLevel] -eq $true) {
            Write-Verbose "[SyncAdminAccountStatus]: - Account should be restored to match referral account status. Attempting to restore account."
            $params = @{
                Method      = 'POST'
                Uri         = "/v1.0/directory/deletedItems/microsoft.graph.user/$($_.Id)/restore"
                ErrorAction = 'Stop'
                Verbose     = $false
                Debug       = $false
            }
            try {
                $null = ./Common_0000__Invoke-MgGraphRequest.ps1 $params
            }
            catch {
                [void] $returnError.Add(( ./Common_0000__Write-Error.ps1 @{
                            Message           = "Failed to restore account $($_.userPrincipalName) ($($_.Id))."
                            ErrorId           = '500'
                            Category          = 'InvalidOperation'
                            RecommendedAction = 'Check the account and its referral account.'
                            CategoryActivity  = 'Account Status Sync'
                            CategoryReason    = "Failed to restore account $($_.userPrincipalName) ($($_.Id))."
                        }))
                return
            }

            Write-Warning "$($_.userPrincipalName) ($($_.Id)): - Restored account due to existing referral account."
            $_ | Add-Member -MemberType NoteProperty -Name "accountLifecycle" -Value @{
                action       = 'Restore'
                actionReason = 'ExistingReferralAccount'
                status       = 'Restored'
            }
            $_.deletedDateTime = [DateTime]::UtcNow
        }
        else {
            Write-Warning "$($_.userPrincipalName) ($($_.Id)): - Account has existing referral account and should be restored, but no automatic restore is performed."
            $_ | Add-Member -MemberType NoteProperty -Name "accountLifecycle" -Value @{
                action       = 'DeferredRestore'
                actionReason = 'ExistingReferralAccount'
                status       = 'ToBeSoftRestored'
            }
        }
        #endregion

        #region Disable account
        if ($_.referralUserAccount.AccountEnabled -eq $false) {
            if ($_.AccountEnabled -eq $false) {
                Write-Debug "[SyncAdminAccountStatus]: - Account does not need to be disabled. Skipping."
                return
            }
            elseif ($LifecycleDisable[$_.securityTierLevel] -eq $true) {
                Write-Verbose "[SyncAdminAccountStatus]: - $($_.userPrincipalName) - Account is enabled and referral account is disabled. Attempting to disable account."

                $params = @{
                    Method      = 'PATCH'
                    Uri         = "/v1.0/users/$($_.Id)"
                    Body        = @{
                        AccountEnabled = $false
                    }
                    ErrorAction = 'Stop'
                    Verbose     = $false
                    Debug       = $false
                }

                try {
                    $null = ./Common_0000__Invoke-MgGraphRequest.ps1 $params
                }
                catch {
                    [void] $returnError.Add(( ./Common_0000__Write-Error.ps1 @{
                                Message           = "Failed to disable account $($_.userPrincipalName) ($($_.Id)) to match referral account."
                                ErrorId           = '500'
                                Category          = 'InvalidOperation'
                                RecommendedAction = 'Check the account and its referral account.'
                                CategoryActivity  = 'Account Status Sync'
                                CategoryReason    = "Failed to disable account $($_.userPrincipalName) ($($_.Id)) to match referral account."
                            }))
                    return
                }

                Write-Warning "$($_.userPrincipalName) ($($_.Id)): - Disabled account to match referral account."
                $_.AccountEnabled = $false
                $_ | Add-Member -MemberType NoteProperty -Name "accountLifecycle" -Value @{
                    action       = 'Disable'
                    actionReason = 'DisabledReferralAccount'
                    status       = 'Disabled'
                }
            }
            else {
                Write-Warning "$($_.userPrincipalName) ($($_.Id)): - Account is enabled and referral account is disabled, but no automatic disabling is performed."
                $_ | Add-Member -MemberType NoteProperty -Name "accountLifecycle" -Value @{
                    action       = 'DeferredDisable'
                    actionReason = 'DisabledReferralAccount'
                    status       = 'ToBeDisabled'
                }
            }
        }
        #endregion

        #region Enable account
        if ($_.referralUserAccount.AccountEnabled -eq $true) {
            if ($_.AccountEnabled -eq $true) {
                Write-Debug "[SyncAdminAccountStatus]: - Account does not need to be enabled. Skipping."
                return
            }
            elseif ($LifecycleEnableAfterDisable[$_.securityTierLevel] -eq $true) {
                Write-Verbose "[SyncAdminAccountStatus]: - $($_.userPrincipalName) - Account is disabled and referral account is enabled. Attempting to enable account."

                $params = @{
                    Method      = 'PATCH'
                    Uri         = "/v1.0/users/$($_.Id)"
                    Body        = @{
                        AccountEnabled = $true
                    }
                    ErrorAction = 'Stop'
                    Verbose     = $false
                    Debug       = $false
                }

                try {
                    $null = ./Common_0000__Invoke-MgGraphRequest.ps1 $params
                }
                catch {
                    [void] $returnError.Add(( ./Common_0000__Write-Error.ps1 @{
                                Message           = "Failed to enable account $($_.userPrincipalName) ($($_.Id)) to match referral account."
                                ErrorId           = '500'
                                Category          = 'InvalidOperation'
                                RecommendedAction = 'Check the account and its referral account.'
                                CategoryActivity  = 'Account Status Sync'
                                CategoryReason    = "Failed to enable account $($_.userPrincipalName) ($($_.Id)) to match referral account."
                            }))
                    return
                }

                Write-Warning "$($_.userPrincipalName) ($($_.Id)): - Enabled account to match referral account."
                $_.AccountEnabled = $true
                $_ | Add-Member -MemberType NoteProperty -Name "accountLifecycle" -Value @{
                    action       = 'Enable'
                    actionReason = 'EnabledReferralAccount'
                    status       = 'Enabled'
                }
            }
            else {
                Write-Warning "$($_.userPrincipalName) ($($_.Id)): - Account is disabled and referral account is enabled, but no automatic enabling is performed."
                $_ | Add-Member -MemberType NoteProperty -Name "accountLifecycle" -Value @{
                    action       = 'DeferredEnable'
                    actionReason = 'EnabledReferralAccount'
                    status       = 'ToBeEnabled'
                }
            }
        }
        #endregion

        if ($null -ne $_.accountLifecycle) {
            [void] $returnOutput.Add($_)
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
$return.Job.EndTime = [DateTime]::UtcNow
$return.Job.Runtime = $return.Job.EndTime - $return.Job.StartTime
$return.Job.Waittime = $return.Job.StartTime - $return.Job.CreationTime

Write-Verbose "Total Waittime: $([math]::Floor($return.Job.Waittime.TotalSeconds)) sec ($([math]::Round($return.Job.Waittime.TotalMinutes, 1)) min)"
Write-Verbose "Total ConcurrentJobsTime: $([math]::Floor($return.Job.ConcurrentJobsTime.TotalSeconds)) sec ($([math]::Round($return.Job.ConcurrentJobsTime.TotalMinutes, 1)) min)"
Write-Verbose "Total Runtime: $([math]::Floor($return.Job.Runtime.TotalSeconds)) sec ($([math]::Round($return.Job.Runtime.TotalMinutes, 1)) min)"

if (
    ($OutText -eq $true) -or
    (($PSBoundParameters.Keys -contains 'OutJson') -and ($OutJson -eq $false)) -or
    (($PSBoundParameters.Keys -contains 'OutCsv') -and ($OutCsv -eq $false))
) {
    if ($concurrentJobsTimeoutError) { Throw 'Concurrent jobs timeout error detected. Please try again later.' }
    Write-Output $return.Output.userPrincipalName
    return
}

if ($OutJson) { ./Common_0000__Write-JsonOutput.ps1 $return; if ($concurrentJobsTimeoutError) { Throw 'Concurrent jobs timeout error detected. Please try again later.' }; return }

if ($OutCsv) {
    if ($return.Output.Count -eq 0) { return }

    $properties = @{
        'lastSuccessfulSignInDateTime'    = 'signInActivity.lastSuccessfulSignInDateTime'
        'lifecycleAction'                 = 'accountLifecycle.action'
        'lifecycleActionReason'           = 'accountLifecycle.actionReason'
        'lifecycleStatus'                 = 'accountLifecycle.status'

        'refDisplayName'                  = 'referralUserAccount.displayName'
        'refUserPrincipalName'            = 'referralUserAccount.userPrincipalName'
        'refOnPremisesSamAccountName'     = 'referralUserAccount.onPremisesSamAccountName'
        'refId'                           = 'referralUserAccount.id'
        'refAccountEnabled'               = 'referralUserAccount.accountEnabled'
        'refCreatedDateTime'              = 'referralUserAccount.createdDateTime'
        'refDeletedDateTime'              = 'referralUserAccount.deletedDateTime'
        'refMail'                         = 'referralUserAccount.mail'
        'refLastSuccessfulSignInDateTime' = 'referralUserAccount.signInActivity.lastSuccessfulSignInDateTime'

        'managerDisplayName'              = 'referralUserAccount.manager.displayName'
        'managerUserPrincipalName'        = 'referralUserAccount.manager.userPrincipalName'
        'managerOnPremisesSamAccountName' = 'referralUserAccount.manager.onPremisesSamAccountName'
        'managerId'                       = 'referralUserAccount.manager.id'
        'managerAccountEnabled'           = 'referralUserAccount.manager.accountEnabled'
        'managerMail'                     = 'referralUserAccount.manager.mail'
    }

    ./Common_0000__Write-CsvOutput.ps1 -InputObject (
        $return.Output | & {
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
                    'lastSuccessfulSignInDateTime'
                    'lifecycleAction'
                    'lifecycleActionReason'
                    'lifecycleStatus'

                    'refDisplayName'
                    'refUserPrincipalName'
                    'refOnPremisesSamAccountName'
                    'refId'
                    'refAccountEnabled'
                    'refCreatedDateTime'
                    'refDeletedDateTime'
                    'refMail'
                    'refLastSuccessfulSignInDateTime'

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
            $baseUri + '/' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '_Invoke-Scheduled-CloudAdministrator-AccountLifecycleManagement.csv' + $uri.Query
        }
    )
    return
}

if ($VerbosePreference -ne 'Continue') { Write-Output "Success = $($return.Success)" }
if ($concurrentJobsTimeoutError) { Throw 'Concurrent jobs timeout error detected. Please try again later.' }
#endregion ---------------------------------------------------------------------
