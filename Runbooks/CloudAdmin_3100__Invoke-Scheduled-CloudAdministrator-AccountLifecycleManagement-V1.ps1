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

.OUTPUTS
    Output may be requested by using one of the parameters -OutObject or -OutputJson.
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

#region [COMMON] FUNCTIONS -----------------------------------------------------
function Get-ReferralUser {
    param(
        # Specifies the user principal name or object ID of the referral user.
        [Parameter(Mandatory = $true)]
        [string] $ReferralUserId
    )

    $params = @{
        Method      = 'GET'
        Uri         = 'https://graph.microsoft.com/v1.0/users?$filter={0}&$select={1}&$expand={2}' -f @(
            "id eq '$($ReferralUserId)'"

            @(
                'id'
                'displayName'
                'userPrincipalName'
                'accountEnabled'
                'mail'
                'onPremisesExtensionAttributes'
            ) -join ','

            @(
                'manager'
            ) -join ','
        )
        OutputType  = 'PSObject'
        ErrorAction = 'Stop'
        Verbose     = $false
        Debug       = $false
    }

    try {
        return @((Invoke-MgGraphRequestWithRetry $params).Value)[0]
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
            elseif ($_.Exception.Response.StatusCode -eq 404) {
                return $null
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
$AllowPrivilegedRoleAdministratorInAzureAutomation = $false
$DirectoryPermissions = ./Common_0003__Confirm-MgDirectoryRoleActiveAssignment.ps1 -AllowPrivilegedRoleAdministratorInAzureAutomation:$AllowPrivilegedRoleAdministratorInAzureAutomation -Roles @(
    # Read user sign-in activity logs
    Write-Verbose '[RequiredMicrosoftEntraDirectoryPermissionsValidation]: - Require directory role: Reports Reader, Directory Scope: /'
    @{
        DisplayName = 'Reports Reader'
        TemplateId  = '4a5d8f65-41da-4de4-8968-e035b65339cf'
    }

    # Change existing Tier 0 Cloud Admin Accounts
    if (
            ([string]::IsNullOrEmpty($DedicatedAccount_Tier0)) -or
            ($DedicatedAccount_Tier0 -ne 'None')
    ) {
        Write-Verbose "[RequiredMicrosoftEntraDirectoryPermissionsValidation]: - Require directory role (Tier 0): User Administrator, Directory Scope: $(if ($AccountRestrictedAdminUnitId_Tier0) { "/administrativeUnits/$AccountRestrictedAdminUnitId_Tier0" } else { '/' })"
        @{
            DisplayName      = 'User Administrator'
            TemplateId       = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
            DirectoryScopeId = if ($AccountRestrictedAdminUnitId_Tier0) { "/administrativeUnits/$AccountRestrictedAdminUnitId_Tier0" } else { '/' }
        }
    }

    # Change existing Tier 1 Cloud Admin Accounts
    if (
            ([string]::IsNullOrEmpty($DedicatedAccount_Tier1)) -or
            ($DedicatedAccount_Tier1 -ne 'None')
    ) {
        Write-Verbose "[RequiredMicrosoftEntraDirectoryPermissionsValidation]: - Require directory role (Tier 1): User Administrator, Directory Scope: $(if ($AccountAdminUnitId_Tier1) { "/administrativeUnits/$AccountAdminUnitId_Tier1" } else { '/' })"
        @{
            DisplayName      = 'User Administrator'
            TemplateId       = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
            DirectoryScopeId = if ($AccountAdminUnitId_Tier1) { "/administrativeUnits/$AccountAdminUnitId_Tier1" } else { '/' }
        }
    }

    # Change existing Tier 2 Cloud Admin Accounts
    if (
            ([string]::IsNullOrEmpty($DedicatedAccount_Tier2)) -or
            ($DedicatedAccount_Tier2 -ne 'None')
    ) {
        Write-Verbose "[RequiredMicrosoftEntraDirectoryPermissionsValidation]: - Require directory role (Tier 2): User Administrator, Directory Scope: $(if ($AccountAdminUnitId_Tier2) { "/administrativeUnits/$AccountAdminUnitId_Tier2" } else { '/' })"
        @{
            DisplayName      = 'User Administrator'
            TemplateId       = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
            DirectoryScopeId = if ($AccountAdminUnitId_Tier2) { "/administrativeUnits/$AccountAdminUnitId_Tier2" } else { '/' }
        }
    }
)
#endregion ---------------------------------------------------------------------

#region [COMMON] INITIALIZE SCRIPT VARIABLES -----------------------------------
$persistentError = $false
$Iteration = 0

$return = @{
    Job = ./Common_0003__Get-AzAutomationJobInfo.ps1
}
if ($JobReference) { $return.Job.Reference = $JobReference }

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
#endregion ---------------------------------------------------------------------

#region Sync admin account status with referral account ------------------------
./CloudAdmin_0000__Common_0001__Get-CloudAdministrator-Account.ps1 -ReferralUserId $ReferralUserId -Tier $Tier -IncludeSoftDeleted $true -ErrorAction Stop | & {
    process {
        Write-Verbose "[SyncAdminAccountStatus]: - Processing account: $($_.userPrincipalName) ($($_.Id))"
        if (
            [string]::IsNullOrEmpty( $_.OnPremisesExtensionAttributes."ExtensionAttribute$ReferenceExtensionAttribute" ) -or
            $_.OnPremisesExtensionAttributes."ExtensionAttribute$ReferenceExtensionAttribute" -notmatch '^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$'
        ) {
            [void] $returnError.Add(( ./Common_0000__Write-Error.ps1 @{
                        Message           = "Cloud Admin Account $($_.userPrincipalName) ($($_.Id)) does not have a valid reference value in OnPremisesExtensionAttributes.ExtensionAttribute$ReferenceExtensionAttribute."
                        ErrorId           = '400'
                        Category          = 'InvalidData'
                        RecommendedAction = 'Check the account and its reference value.'
                        CategoryActivity  = 'Account Status Sync'
                        CategoryReason    = "Account $($_.userPrincipalName) ($($_.Id)) does not have a valid reference value in OnPremisesExtensionAttributes.ExtensionAttribute$ReferenceExtensionAttribute."
                    }))
            return
        }

        if ($_.OnPremisesExtensionAttributes."ExtensionAttribute$AccountTypeExtensionAttribute" -match "^$($TierPrefix[0]).*") {
            $AccountType = 0
        }
        elseif ($_.OnPremisesExtensionAttributes."ExtensionAttribute$AccountTypeExtensionAttribute" -match "^$($TierPrefix[1]).*") {
            $AccountType = 1
        }
        elseif ($_.OnPremisesExtensionAttributes."ExtensionAttribute$AccountTypeExtensionAttribute" -match "^$($TierPrefix[2]).*") {
            $AccountType = 2
        }
        else {
            [void] $returnError.Add(( ./Common_0000__Write-Error.ps1 @{
                        Message           = "Cloud Admin Account $($_.userPrincipalName) ($($_.Id)) does not have a valid account type value in OnPremisesExtensionAttributes.ExtensionAttribute$AccountTypeExtensionAttribute."
                        ErrorId           = '400'
                        Category          = 'InvalidData'
                        RecommendedAction = 'Check the account and its account type value.'
                        CategoryActivity  = 'Account Status Sync'
                        CategoryReason    = "Account $($_.userPrincipalName) ($($_.Id)) does not have a valid account type value in OnPremisesExtensionAttributes.ExtensionAttribute$AccountTypeExtensionAttribute."
                    }))
            return
        }
        Write-Verbose "[SyncAdminAccountStatus]: - This is a Tier $AccountType account"

        try {
            Write-Verbose "[SyncAdminAccountStatus]: - Searching for reference account id: $($_.OnPremisesExtensionAttributes."ExtensionAttribute$ReferenceExtensionAttribute")"
            $refUserObj = Get-ReferralUser -ReferralUserId $_.OnPremisesExtensionAttributes."ExtensionAttribute$ReferenceExtensionAttribute"
        }
        catch {
            Throw $_
        }

        if ($_.deletedDateTime -and $null -eq $refUserObj) {
            Write-Verbose "[SyncAdminAccountStatus]: - Account is soft-deleted and has no existing referring account. Skipping."
            return
        }

        if ($_.deletedDateTime -and $null -ne $refUserObj) {
            Write-Verbose "[SyncAdminAccountStatus]: - Account is soft-deleted, but no automatic recovery is performed. Skipping."
            return
        }

        $data = @{
            Input             = @{}
            Manager           = @{}
            Id                = $_.Id
            UserPrincipalName = $_.UserPrincipalName
            DisplayName       = $_.DisplayName
            AccountEnabled    = $_.AccountEnabled
            Mail              = $_.Mail
        }

        #region Delete account
        if ($null -eq $refUserObj) {
            Write-Verbose "[SyncAdminAccountStatus]: - Reference account not found for account: $($_.userPrincipalName) ($($_.Id))"

            $params = @{
                Method      = 'DELETE'
                Uri         = "https://graph.microsoft.com/v1.0/users/$($_.Id)"
                ErrorAction = 'Stop'
                Verbose     = $false
                Debug       = $false
            }

            try {
                $null = Invoke-MgGraphRequestWithRetry $params
            }
            catch {
                [void] $returnError.Add(( ./Common_0000__Write-Error.ps1 @{
                            Message           = "Failed to update account $($_.userPrincipalName) ($($_.Id)) property 'AccountEnabled' to match reference account."
                            ErrorId           = '500'
                            Category          = 'InvalidOperation'
                            RecommendedAction = 'Check the account and its reference account.'
                            CategoryActivity  = 'Account Status Sync'
                            CategoryReason    = "Failed to update account $($_.userPrincipalName) ($($_.Id)) property 'AccountEnabled' to match reference account."
                        }))
                return
            }

            $data.deletedDateTime = (Get-Date).ToUniversalTime()
            Write-Warning "$($_.userPrincipalName) ($($_.Id)): - Deleted account due to missing reference account."
            [void] $returnOutput.Add($data)
            return
        }
        #endregion

        Write-Verbose "[SyncAdminAccountStatus]: - $($_.userPrincipalName) - Found reference account: $($refUserObj.UserPrincipalName) ($($refUserObj.Id))"

        $data.Input = @{
            ReferralUser = @{
                Id                = $refUserObj.Id
                UserPrincipalName = $refUserObj.UserPrincipalName
                Mail              = $refUserObj.Mail
                DisplayName       = $refUserObj.DisplayName
                AccountEnabled    = $refUserObj.AccountEnabled
            }
            Tier         = $AccountType
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
            Write-Verbose "[SyncAdminAccountStatus]: - $($_.userPrincipalName) - Property 'AccountEnabled' is out of sync with reference account."
            $params = @{
                Method      = 'PATCH'
                Uri         = "https://graph.microsoft.com/v1.0/users/$($_.Id)"
                Body        = @{
                    AccountEnabled = $refUserObj.AccountEnabled
                }
                OutputType  = 'PSObject'
                ErrorAction = 'Stop'
                Verbose     = $false
                Debug       = $false
            }

            try {
                $null = Invoke-MgGraphRequestWithRetry $params
            }
            catch {
                [void] $returnError.Add(( ./Common_0000__Write-Error.ps1 @{
                            Message           = "Failed to update account $($_.userPrincipalName) ($($_.Id)) property 'AccountEnabled' to match reference account."
                            ErrorId           = '500'
                            Category          = 'InvalidOperation'
                            RecommendedAction = 'Check the account and its reference account.'
                            CategoryActivity  = 'Account Status Sync'
                            CategoryReason    = "Failed to update account $($_.userPrincipalName) ($($_.Id)) property 'AccountEnabled' to match reference account."
                        }))
                return
            }

            Write-Warning "$($_.userPrincipalName) ($($_.Id)): - Updated property AccountEnabled to '$($refUserObj.AccountEnabled)' to match reference account."
            $data.AccountEnabled = $refUserObj.AccountEnabled
            [void] $returnOutput.Add($data)
        }
        else {
            Write-Verbose "[SyncAdminAccountStatus]: - $($_.userPrincipalName) - Property 'AccountEnabled' is in sync with reference account."
            Write-Information "$($_.userPrincipalName) ($($_.Id)): - Property AccountEnabled is in sync with reference account." -InformationAction Continue
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
