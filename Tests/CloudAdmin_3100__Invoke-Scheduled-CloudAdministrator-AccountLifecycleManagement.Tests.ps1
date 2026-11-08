BeforeAll {
    . (Join-Path $PSScriptRoot 'Helpers/FakeGraph.ps1')

    $script:Runbook = Join-Path $PSScriptRoot '../Runbooks/CloudAdmin_3100__Invoke-Scheduled-CloudAdministrator-AccountLifecycleManagement.ps1'
    $script:FrameworkRunbooks = if ($env:AZAUTO_FW_RUNBOOKS) { $env:AZAUTO_FW_RUNBOOKS } else { Join-Path $PSScriptRoot '../../AzAuto-Common-Runbook-FW/Runbooks' }

    # Stubs for every child runbook except the framework's request runbook, which runs for real.
    $script:Stubs = @{
        'Common_0001__Connect-MgGraph.ps1'                                         = 'param($Scopes)'
        'Common_0002__Import-AzAutomationVariableToPSEnv.ps1'                      = ''
        'CloudAdmin_0000__Common_0000__Get-ConfigurationConstants.ps1'             = '@()'
        'Common_0000__Convert-PSEnvToPSScriptVariable.ps1'                         = @'
param($Variable)
foreach ($tier in 0..2) {
    foreach ($name in 'LifecycleDelete', 'LifecycleRestoreAfterDelete', 'LifecycleDisable', 'LifecycleEnableAfterDisable') {
        Set-Variable -Scope 1 -Name "${name}_Tier$tier" -Value ($global:LifecycleTest.Settings[$name] -eq $true)
    }
}
Set-Variable -Scope 1 -Name AccountRestrictedAdminUnitId_Tier0 -Value 'au0'
Set-Variable -Scope 1 -Name AccountAdminUnitId_Tier1 -Value 'au1'
Set-Variable -Scope 1 -Name AccountAdminUnitId_Tier2 -Value 'au2'
'@
        'Common_0002__Wait-AzAutomationConcurrentJob.ps1'                          = '$true'
        'Common_0003__Confirm-MgDirectoryRoleActiveAssignment.ps1'                 = 'param($AllowPrivilegedRoleAdministratorInAzureAutomation, $Roles) $global:LifecycleTest.Roles = $Roles'
        'Common_0002__Get-AzAutomationJobInfo.ps1'                                 = '@{ StartTime = [DateTime]::UtcNow; CreationTime = [DateTime]::UtcNow; Runbook = @{} }'
        'Common_0000__Write-JsonOutput.ps1'                                        = 'param($Object) $global:LifecycleTest.Result = $Object'
        'Common_0000__Write-Error.ps1'                                             = 'param($Parameters) $Parameters.Message'
        'CloudAdmin_0000__Common_0001__Get-CloudAdminAccountsByPrimaryAccount.ps1' = 'param($ReferralUserId, $Tier, $ExpandReferralUserId) $global:LifecycleTest.Accounts'
    }

    # Stands in for the Microsoft Graph cmdlet that the framework's request runbook calls.
    function Invoke-MgGraphRequest {
        [CmdletBinding()]
        param($Method = 'GET', $Uri, $Body)
        [void] $global:LifecycleTest.Calls.Add("$Method $Uri")
        foreach ($id in $global:LifecycleTest.MissingIds) {
            if ($Uri -match [regex]::Escape($id)) { throw [FakeGraphException]::new(404, 'Request_ResourceNotFound', 'Resource does not exist.') }
        }
        if ($Method -in 'GET', 'POST') { @{ id = 'user' } }
    }

    function New-Account {
        param(
            [string] $Id,
            [bool] $Enabled = $true,
            [string] $Deleted,
            [string] $ReferralId = [guid]::NewGuid().Guid,
            $ReferralEnabled = $true,
            [string] $ReferralDeleted
        )
        [ordered] @{
            securityTierLevel   = 1
            userPrincipalName   = "$Id@contoso.com"
            id                  = $Id
            accountEnabled      = $Enabled
            deletedDateTime     = if ($Deleted) { $Deleted } else { $null }
            referralUserAccount = [ordered] @{
                id              = $ReferralId
                accountEnabled  = $ReferralEnabled
                deletedDateTime = if ($ReferralDeleted) { $ReferralDeleted } else { $null }
            }
        }
    }

    # One folder for all tests: the runbook, the framework's request runbook and the stubs. Each test only sets $global:LifecycleTest.
    $script:Folder = Join-Path $TestDrive 'runbooks'
    New-Item -ItemType Directory -Path $script:Folder | Out-Null
    Copy-Item -Path $script:Runbook -Destination (Join-Path $script:Folder 'runbook.ps1')
    Copy-Item -Path (Join-Path $script:FrameworkRunbooks 'Common_0001__Invoke-MgGraphRequest.ps1') -Destination $script:Folder
    foreach ($name in $script:Stubs.Keys) { Set-Content -Path (Join-Path $script:Folder $name) -Value $script:Stubs[$name] }

    function Invoke-Lifecycle {
        param(
            [string[]] $On = @(),
            [array] $Accounts,
            [string[]] $MissingIds = @()
        )
        $settings = @{}
        foreach ($name in $On) { $settings[$name] = $true }
        $global:LifecycleTest = @{
            Settings   = $settings
            Accounts   = $Accounts
            MissingIds = $MissingIds
            Calls      = [System.Collections.ArrayList]::new()
            Result     = $null
            Roles      = $null
        }
        Push-Location $script:Folder
        try { $null = & ./runbook.ps1 -OutJson $true -WarningAction SilentlyContinue 2>&1 }
        finally { Pop-Location }
        $global:LifecycleTest
    }

    function Get-Lifecycle ($Run, $Id) {
        ($Run.Result.Output | Where-Object { $_.id -eq $Id }).accountLifecycle
    }

    $script:AllOn = 'LifecycleDelete', 'LifecycleRestoreAfterDelete', 'LifecycleDisable', 'LifecycleEnableAfterDisable'
}

AfterAll {
    Remove-Variable -Name LifecycleTest -Scope Global -ErrorAction SilentlyContinue
}

Describe 'CloudAdmin_3100 with every lifecycle setting on' {
    It 'soft-deletes an account without a primary account' {
        $run = Invoke-Lifecycle -On $script:AllOn -Accounts @(New-Account -Id 'A' -ReferralId '')
        $run.Calls | Should -Contain 'DELETE /v1.0/users/A'
        (Get-Lifecycle $run 'A').status | Should -Be 'SoftDeleted'
    }

    It 'sends the delete for each account whose primary account is soft-deleted' {
        $run = Invoke-Lifecycle -On $script:AllOn -Accounts @(
            New-Account -Id 'A' -ReferralId ''
            New-Account -Id 'B' -ReferralDeleted '2026-01-01T00:00:00Z'
        )
        $run.Calls | Where-Object { $_ -like 'DELETE *' } | Should -Be @('DELETE /v1.0/users/A', 'DELETE /v1.0/users/B')
        (Get-Lifecycle $run 'B').actionReason | Should -Be 'SoftDeletedReferralAccount'
    }

    It 'restores an account and leaves enabling and disabling to the next run' {
        $run = Invoke-Lifecycle -On $script:AllOn -Accounts @(New-Account -Id 'D' -Deleted '2026-01-01T00:00:00Z' -ReferralEnabled $false)
        $run.Calls | Should -Contain 'POST /v1.0/directory/deletedItems/D/restore'
        $run.Calls | Where-Object { $_ -like 'PATCH *' } | Should -BeNullOrEmpty
        (Get-Lifecycle $run 'D').status | Should -Be 'Restored'
    }

    It 'disables an account whose primary account is disabled' {
        $run = Invoke-Lifecycle -On $script:AllOn -Accounts @(New-Account -Id 'E' -ReferralEnabled $false)
        $run.Calls | Should -Contain 'PATCH /v1.0/users/E'
        (Get-Lifecycle $run 'E').status | Should -Be 'Disabled'
    }

    It 'enables an account whose primary account is enabled' {
        $run = Invoke-Lifecycle -On $script:AllOn -Accounts @(New-Account -Id 'F' -Enabled $false)
        $run.Calls | Should -Contain 'PATCH /v1.0/users/F'
        (Get-Lifecycle $run 'F').status | Should -Be 'Enabled'
    }

    It 'reports a restore of a user that no longer exists as an error' {
        $run = Invoke-Lifecycle -On $script:AllOn -Accounts @(New-Account -Id 'G' -Deleted '2026-01-01T00:00:00Z') -MissingIds 'G'
        $run.Result.Output | Should -BeNullOrEmpty
        $run.Result.Error | Should -Be 'Failed to restore account G@contoso.com (G).'
    }

    It 'reports a change to a user that no longer exists as an error, without sending it' {
        $run = Invoke-Lifecycle -On $script:AllOn -Accounts @(New-Account -Id 'H' -ReferralEnabled $false) -MissingIds 'H'
        $run.Calls | Where-Object { $_ -like 'PATCH *' } | Should -BeNullOrEmpty
        $run.Result.Error | Should -Be 'Failed to disable account H@contoso.com (H) to match referral account.'
    }

    It 'leaves an account alone whose primary reference is not an object ID' {
        $run = Invoke-Lifecycle -On $script:AllOn -Accounts @(New-Account -Id 'K' -Deleted '2026-01-01T00:00:00Z' -ReferralId 'someone@contoso.com' -ReferralEnabled $null)
        $run.Calls | Should -BeNullOrEmpty
        (Get-Lifecycle $run 'K').status | Should -Be 'ToBeReviewed'
    }

    It 'requires Privileged Authentication Administrator at tenant scope for restore, and on the admin units' {
        $run = Invoke-Lifecycle -On $script:AllOn -Accounts @()
        $scopes = $run.Roles | Where-Object { $_ -is [hashtable] -and $_.DisplayName -eq 'Privileged Authentication Administrator' } | ForEach-Object { $_.DirectoryScopeId }
        $scopes | Sort-Object -Unique | Should -Be @('/', '/administrativeUnits/au0', '/administrativeUnits/au1', '/administrativeUnits/au2')
    }
}

Describe 'CloudAdmin_3100 with every lifecycle setting off' {
    It 'changes nothing and reports each action as deferred' {
        $run = Invoke-Lifecycle -Accounts @(
            New-Account -Id 'A' -ReferralId ''
            New-Account -Id 'B' -ReferralDeleted '2026-01-01T00:00:00Z'
            New-Account -Id 'D' -Deleted '2026-01-01T00:00:00Z'
            New-Account -Id 'E' -ReferralEnabled $false
            New-Account -Id 'F' -Enabled $false
        )
        $run.Calls | Where-Object { $_ -notlike 'GET *' } | Should -BeNullOrEmpty
        ($run.Result.Output | ForEach-Object { $_.accountLifecycle.status }) | Should -Be @('ToBeSoftDeleted', 'ToBeSoftDeleted', 'ToBeSoftRestored', 'ToBeDisabled', 'ToBeEnabled')
    }

    It 'does not require Privileged Authentication Administrator at tenant scope' {
        $run = Invoke-Lifecycle -Accounts @()
        $run.Roles | Where-Object { $_ -is [hashtable] -and $_.DisplayName -eq 'Privileged Authentication Administrator' -and $_.DirectoryScopeId -eq '/' } | Should -BeNullOrEmpty
    }
}

Describe 'CloudAdmin_3100 with only disabling on' {
    It 'keeps a pending soft-delete visible after it disables the account' {
        $run = Invoke-Lifecycle -On 'LifecycleDisable' -Accounts @(New-Account -Id 'C' -ReferralEnabled $false -ReferralDeleted '2026-01-01T00:00:00Z')
        $run.Calls | Should -Contain 'PATCH /v1.0/users/C'
        (Get-Lifecycle $run 'C').status | Should -Be 'DisabledToBeSoftDeleted'
    }
}

Describe 'CloudAdmin_0000__Common_0000__Get-ConfigurationConstants' {
    BeforeAll {
        $script:Constants = & (Join-Path $PSScriptRoot '../Runbooks/CloudAdmin_0000__Common_0000__Get-ConfigurationConstants.ps1')
    }

    It 'reads the lifecycle setting <Variable> from <Source>' -ForEach @(
        foreach ($tier in 0..2) {
            foreach ($name in 'LifecycleDelete', 'LifecycleRestoreAfterDelete', 'LifecycleDisable', 'LifecycleEnableAfterDisable') {
                @{ Variable = "${name}_Tier$tier"; Source = "AV_CloudAdminTier${tier}_$name" }
            }
        }
    ) {
        ($script:Constants | Where-Object { $_.mapToVariable -eq $Variable }).sourceName | Should -Be $Source
    }
}
