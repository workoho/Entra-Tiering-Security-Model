<#PSScriptInfo
.VERSION 1.1.0
.GUID 9be21e88-4210-47d9-a533-3beb443de48a
.AUTHOR Julian Pawlowski
.COMPANYNAME Workoho GmbH
.COPYRIGHT © 2024 Workoho GmbH
.TAGS
.LICENSEURI https://github.com/workoho/Entra-Tiering-Security-Model/blob/main/LICENSE.txt
.PROJECTURI https://github.com/workoho/Entra-Tiering-Security-Model
.ICONURI
.EXTERNALMODULEDEPENDENCIES Microsoft.Graph.Authentication
.REQUIREDSCRIPTS CloudAdmin_0000__Common_0000__Get-ConfigurationConstants.ps1,CloudAdmin_0000__Common_0001__Get-CloudAdminAccountsByPrimaryAccount.ps1
.EXTERNALSCRIPTDEPENDENCIES https://github.com/workoho/AzAuto-Common-Runbook-FW
.RELEASENOTES
    Version 1.1.0 (2024-06-17)
    - Update PSScriptInfo.
#>

<#
.SYNOPSIS
    Retrieves the referenced primary user account of a cloud admin account.

.DESCRIPTION
    This script retrieves the primary user account of a cloud admin account from the Microsoft Graph API.

.PARAMETER CloudAdminUserId
    Specifies the object ID of the cloud admin account that is used to search for the referenced primary user account.
    May be an array, or a comma-separated string of object IDs or user principal names.
    If not provided, all cloud admin accounts are retrieved.

.PARAMETER Tier
    When provided without CloudAdminUserId, all cloud admin accounts of the specified security tier level are returned. Must be a value between 0 and 2.

    When provided together with CloudAdminUserId, it validates the cloud admin account to filter out accounts that do not match the specified security tier level.
    In case only one security tier level is specified, it is applied to all cloud admin accounts.
    Otherwise, the number of security tier levels must match the number of cloud admin accounts.

    May be an array, or a comma-separated string of security tier levels.

.PARAMETER OutJson
    Specifies whether to output the result as JSON.

.PARAMETER OutCsv
    Specifies whether to output the result as CSV.
    The 'cloudAdminAccounts' property is expanded into separate columns for each security tier level.
    Also, the 'signInActivity' and 'onPremisesExtensionAttributes' properties are expanded into separate columns.

    If the AV_CloudAdmin_StorageUri variable is set in the Azure Automation account, the CSV file is stored in the specified Azure Blob Storage container or Azure File Share.
    The file name is prefixed with the current date and time in the format 'yyyyMMddTHHmmssfffZ'.
    Note that the managed identity of the Azure Automation account must have the necessary permissions to write to the specified storage account.
    That is, the managed identity must have the 'Storage Blob Data Contributor' role for a blob container or the 'Storage File Data SMB Share Contributor' role for a file share.
    Remember that general roles like 'Owner' or 'Contributor' do not grant write access to storage accounts.

.PARAMETER OutText
    Specifies whether to output the result as text.
    This will only output the user principal name of the primary user accounts.

.OUTPUTS
    Output may be requested in JSON, CSV, or text format by using one of the parameters -OutJson, -OutCsv, or -OutText.
    The output includes properties such as 'userPrincipalName', 'accountEnabled', 'lastSuccessfulSignInDateTime', etc.

    If none of these parameters are used, the script returns an object array where each object represents a primary user account
    and its associated cloud admin accounts in the 'cloudAdminAccounts' property.
#>

[CmdletBinding()]
Param (
    [array] $CloudAdminUserId,
    [array] $Tier,
    [boolean] $OutJson,
    [boolean] $OutCsv,
    [boolean] $OutText
)

if ($PSCommandPath) { Write-Verbose "---START of $((Get-Item $PSCommandPath).Name), $((Test-ScriptFileInfo $PSCommandPath | Select-Object -Property Version, Guid | & { process{$_.PSObject.Properties | & { process{$_.Name + ': ' + $_.Value} }} }) -join ', ') ---" }
$StartupVariables = (Get-Variable | & { process { $_.Name } })      # Remember existing variables so we can cleanup ours at the end of the script

#region [COMMON] PARAMETER VALIDATION ------------------------------------------

# Allow comma-separated values for CloudAdminUserId and Tier
$CloudAdminUserId = if ([string]::IsNullOrEmpty($CloudAdminUserId)) { @() } else {
    @($CloudAdminUserId) | & { process { $_ -split '\s*,\s*' } } | & { process { if (-not [string]::IsNullOrEmpty($_)) { $_ } } }
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
                    Throw "[GetPrimaryAccountsByCloudAdminAccount]: - Auto-converting of Tier string to Int32 failed: $_"
                }
            }
        }
    }
}

if (
    ($CloudAdminUserId.Count -gt 1) -and
    ($Tier.Count -gt 1) -and
    ($CloudAdminUserId.Count -ne $Tier.Count)
) {
    Throw 'CloudAdminUserId and Tier must contain the same number of items for batch processing.'
}
#endregion ---------------------------------------------------------------------

#region [COMMON] OPEN CONNECTIONS: Microsoft Graph -----------------------------
./Common_0001__Connect-MgGraph.ps1 -Scopes @(
    # Read-only permissions
    'AuditLog.Read.All'
    'Directory.Read.All'
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
$TierLevel = @{
    $AccountTypeExtensionAttributePrefix_Tier0 = 0
    $AccountTypeExtensionAttributePrefix_Tier1 = 1
    $AccountTypeExtensionAttributePrefix_Tier2 = 2
}
$TierPrefix = @(
    $AccountTypeExtensionAttributePrefix_Tier0
    $AccountTypeExtensionAttributePrefix_Tier1
    $AccountTypeExtensionAttributePrefix_Tier2
)
$return = [System.Collections.ArrayList]::new()
#endregion ---------------------------------------------------------------------

#region Get all Cloud Admin User Accounts --------------------------------------
if ($null -eq $CloudAdminUserId -or $CloudAdminUserId.Count -eq 0) {
    $CloudAdminUserId = ./CloudAdmin_0000__Common_0001__Get-CloudAdminAccountsByPrimaryAccount.ps1 -Tier $Tier
}
#endregion ---------------------------------------------------------------------

#region Find Primary User Accounts ---------------------------------------------
if ($CloudAdminUserId.Count -gt 0) {
    $i = 0
    @($CloudAdminUserId) | & {
        process {
            try {
                if ($_ -is [PSCustomObject]) {
                    $userObj = $_
                    Write-Verbose "[$i]: - Processing userId '$($_.Id)'."
                }
                else {
                    Write-Verbose "[$i]: - Processing userId '$_'."

                    try {
                        $userObj = @(
                            ./Common_0002__Find-MgUserWithSoftDeleted.ps1 -UserId $_ -Property @(
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
                        )[0]
                    }
                    catch {
                        Throw $_
                    }

                    if ($null -eq $userObj) {
                        Write-Error "userId '$_' not found."
                        return
                    }
                }

                if (
                    $null -eq $userObj.onPremisesExtensionAttributes."extensionAttribute$ReferenceExtensionAttribute" -or
                    $userObj.onPremisesExtensionAttributes."extensionAttribute$ReferenceExtensionAttribute" -notmatch '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$'
                ) {
                    Write-Error "userId '$($userObj.Id)' is not a cloud admin account: No reference extension attribute 'extensionAttribute$ReferenceExtensionAttribute' set."
                    return
                }

                if (
                    $null -eq $userObj.onPremisesExtensionAttributes."extensionAttribute$AccountTypeExtensionAttribute" -or
                    [string]::IsNullOrEmpty($userObj.onPremisesExtensionAttributes."extensionAttribute$AccountTypeExtensionAttribute".Trim())
                ) {
                    Write-Error "userId '$($userObj.Id)' is not a cloud admin account: No account type extension attribute 'extensionAttribute$AccountTypeExtensionAttribute' set."
                    return
                }

                $securityTierLevel = $null
                foreach ($key in $TierLevel.Keys) {
                    if ($userObj.onPremisesExtensionAttributes."extensionAttribute$AccountTypeExtensionAttribute" -like "$key*") {
                        $securityTierLevel = $TierLevel[$key]
                        break
                    }
                }

                if ($null -eq $securityTierLevel) {
                    Write-Error "userId '$($userObj.Id)' has an invalid security tier level marker: Account type extension attribute 'extensionAttribute$AccountTypeExtensionAttribute' value '$($userObj.onPremisesExtensionAttributes."extensionAttribute$AccountTypeExtensionAttribute")' is not valid."
                }

                if ($null -ne $Tier) {
                    if ($Tier.Count -eq 1) {
                        if ($Tier[0] -ne $securityTierLevel) {
                            Write-Warning "userId '$($userObj.Id)' has defined security tier level '$securityTierLevel' but does not validate to the specified security tier level '$($Tier[0])'."
                            return
                        }
                    }
                    else {
                        if ($Tier[$i] -ne $securityTierLevel) {
                            Write-Warning "userId '$_' has defined security tier level '$securityTierLevel' but does not validate to the specified security tier level '$($Tier[$i])'."
                            return
                        }
                    }
                }

                if ($null -eq $userObj.securityTierLevel) {
                    $userObj | Add-Member -MemberType NoteProperty -Name 'securityTierLevel' -Value $securityTierLevel
                }

                try {
                    $refUserObj = @(
                        ./Common_0002__Find-MgUserWithSoftDeleted.ps1 -UserId $userObj.onPremisesExtensionAttributes."extensionAttribute$ReferenceExtensionAttribute" -Property @(
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
                                    'onPremisesSamAccountName'
                                    'id'
                                    'accountEnabled'
                                    'mail'
                                )
                            }
                        )
                    )[0]
                }
                catch {
                    Throw $_
                }

                if ($null -eq $refUserObj) {
                    Write-Verbose "$($userObj.userPrincipalName): - Referral user Id '$($userObj.onPremisesExtensionAttributes."extensionAttribute$ReferenceExtensionAttribute")' not found."
                    return
                }

                if ($null -eq $userObj.referralUserAccount) {
                    $userObj | Add-Member -MemberType NoteProperty -Name 'referralUserAccount' -Value (
                        [PSCustomObject] @{
                            id = $refUserObj.id
                        }
                    )
                }

                $existingRefUserObj = $return | Where-Object { $_.Id -eq $refUserObj.Id }
                if ($null -eq $existingRefUserObj) {
                    $refUserObj | Add-Member -MemberType NoteProperty -Name 'cloudAdminAccounts' -Value (
                        [System.Collections.ArrayList] @(
                            $userObj
                        )
                    )
                    [void] $return.Add($refUserObj)
                }
                else {
                    $existingRefUserObj.cloudAdminAccounts.Add($userObj)
                }
            }
            finally {
                $i++
                Clear-Variable -Name existingRefUserObj -ErrorAction SilentlyContinue
                Clear-Variable -Name userObj -ErrorAction SilentlyContinue
                Clear-Variable -Name refUserObj -ErrorAction SilentlyContinue
                [System.GC]::Collect()
                [System.GC]::WaitForPendingFinalizers()
            }
        }
    }
}

Write-Verbose "[Get-ReferralUser-Account]: - Found $($return.Count) reference user accounts."
#endregion ---------------------------------------------------------------------

Get-Variable | Where-Object { $StartupVariables -notcontains $_.Name } | & { process { Remove-Variable -Scope 0 -Name $_.Name -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue -Verbose:$false -Debug:$false -Confirm:$false -WhatIf:$false } }        # Delete variables created in this script to free up memory for tiny Azure Automation sandbox
if ($PSCommandPath) { Write-Verbose "-----END of $((Get-Item $PSCommandPath).Name) ---" }

if ($OutJson) { if ($return.Count -eq 0) { return '[]' }; ./Common_0000__Write-JsonOutput.ps1 $return; return }

if ($OutCsv) {
    if ($return.Count -eq 0) {
        return 'No referenced primary user accounts found.'
    }

    $properties = @{
        'lastSignInDateTime'               = 'signInActivity.lastSignInDateTime'
        'lastNonInteractiveSignInDateTime' = 'signInActivity.lastNonInteractiveSignInDateTime'
        'lastSuccessfulSignInDateTime'     = 'signInActivity.lastSuccessfulSignInDateTime'
        'extensionAttribute1'              = 'onPremisesExtensionAttributes.extensionAttribute1'
        'extensionAttribute2'              = 'onPremisesExtensionAttributes.extensionAttribute2'
        'extensionAttribute3'              = 'onPremisesExtensionAttributes.extensionAttribute3'
        'extensionAttribute4'              = 'onPremisesExtensionAttributes.extensionAttribute4'
        'extensionAttribute5'              = 'onPremisesExtensionAttributes.extensionAttribute5'
        'extensionAttribute6'              = 'onPremisesExtensionAttributes.extensionAttribute6'
        'extensionAttribute7'              = 'onPremisesExtensionAttributes.extensionAttribute7'
        'extensionAttribute8'              = 'onPremisesExtensionAttributes.extensionAttribute8'
        'extensionAttribute9'              = 'onPremisesExtensionAttributes.extensionAttribute9'
        'extensionAttribute10'             = 'onPremisesExtensionAttributes.extensionAttribute10'
        'extensionAttribute11'             = 'onPremisesExtensionAttributes.extensionAttribute11'
        'extensionAttribute12'             = 'onPremisesExtensionAttributes.extensionAttribute12'
        'extensionAttribute13'             = 'onPremisesExtensionAttributes.extensionAttribute13'
        'extensionAttribute14'             = 'onPremisesExtensionAttributes.extensionAttribute14'
        'extensionAttribute15'             = 'onPremisesExtensionAttributes.extensionAttribute15'
    }

    $cloudAdminAccountProperties = @{
        'displayName'                      = 'displayName'
        'userPrincipalName'                = 'userPrincipalName'
        'id'                               = 'id'
        'accountEnabled'                   = 'accountEnabled'
        'createdDateTime'                  = 'createdDateTime'
        'deletedDateTime'                  = 'deletedDateTime'
        'mail'                             = 'mail'
        'lastSignInDateTime'               = 'signInActivity.lastSignInDateTime'
        'lastNonInteractiveSignInDateTime' = 'signInActivity.lastNonInteractiveSignInDateTime'
        'lastSuccessfulSignInDateTime'     = 'signInActivity.lastSuccessfulSignInDateTime'
        'extensionAttribute1'              = 'onPremisesExtensionAttributes.extensionAttribute1'
        'extensionAttribute2'              = 'onPremisesExtensionAttributes.extensionAttribute2'
        'extensionAttribute3'              = 'onPremisesExtensionAttributes.extensionAttribute3'
        'extensionAttribute4'              = 'onPremisesExtensionAttributes.extensionAttribute4'
        'extensionAttribute5'              = 'onPremisesExtensionAttributes.extensionAttribute5'
        'extensionAttribute6'              = 'onPremisesExtensionAttributes.extensionAttribute6'
        'extensionAttribute7'              = 'onPremisesExtensionAttributes.extensionAttribute7'
        'extensionAttribute8'              = 'onPremisesExtensionAttributes.extensionAttribute8'
        'extensionAttribute9'              = 'onPremisesExtensionAttributes.extensionAttribute9'
        'extensionAttribute10'             = 'onPremisesExtensionAttributes.extensionAttribute10'
        'extensionAttribute11'             = 'onPremisesExtensionAttributes.extensionAttribute11'
        'extensionAttribute12'             = 'onPremisesExtensionAttributes.extensionAttribute12'
        'extensionAttribute13'             = 'onPremisesExtensionAttributes.extensionAttribute13'
        'extensionAttribute14'             = 'onPremisesExtensionAttributes.extensionAttribute14'
        'extensionAttribute15'             = 'onPremisesExtensionAttributes.extensionAttribute15'
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

                if ($_.cloudAdminAccounts.Count -gt 0) {
                    foreach ($cloudAdminAccount in $_.cloudAdminAccounts | Sort-Object -Property securityTierLevel) {
                        foreach ($property in $cloudAdminAccountProperties.GetEnumerator()) {
                            $propertyName = "T$($cloudAdminAccount.securityTierLevel)$($property.Key)"
                            $nestedPropertyPath = $property.Value -split '\.'
                            if ($nestedPropertyPath.count -eq 3) {
                                $_ | Add-Member -NotePropertyName $propertyName -NotePropertyValue $cloudAdminAccount.$($nestedPropertyPath[0]).$($nestedPropertyPath[1]).$($nestedPropertyPath[2])
                            }
                            elseif ($nestedPropertyPath.count -eq 2) {
                                $_ | Add-Member -NotePropertyName $propertyName -NotePropertyValue $cloudAdminAccount.$($nestedPropertyPath[0]).$($nestedPropertyPath[1])
                            }
                            elseif ($nestedPropertyPath.count -eq 1) {
                                $_ | Add-Member -NotePropertyName $propertyName -NotePropertyValue $cloudAdminAccount.$($nestedPropertyPath[0])
                            }
                            else {
                                Throw "Invalid nested property path: $($property.Value)"
                            }
                        }
                    }
                }

                $_ | Select-Object -Property @(
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

                    'T0displayName'
                    'T0userPrincipalName'
                    'T0id'
                    'T0accountEnabled'
                    'T0createdDateTime'
                    'T0deletedDateTime'
                    'T0mail'
                    'T0lastSignInDateTime'
                    'T0lastNonInteractiveSignInDateTime'
                    'T0lastSuccessfulSignInDateTime'
                    'T0extensionAttribute1'
                    'T0extensionAttribute2'
                    'T0extensionAttribute3'
                    'T0extensionAttribute4'
                    'T0extensionAttribute5'
                    'T0extensionAttribute6'
                    'T0extensionAttribute7'
                    'T0extensionAttribute8'
                    'T0extensionAttribute9'
                    'T0extensionAttribute10'
                    'T0extensionAttribute11'
                    'T0extensionAttribute12'
                    'T0extensionAttribute13'
                    'T0extensionAttribute14'
                    'T0extensionAttribute15'

                    'T1displayName'
                    'T1userPrincipalName'
                    'T1id'
                    'T1accountEnabled'
                    'T1createdDateTime'
                    'T1deletedDateTime'
                    'T1mail'
                    'T1lastSignInDateTime'
                    'T1lastNonInteractiveSignInDateTime'
                    'T1lastSuccessfulSignInDateTime'
                    'T1extensionAttribute1'
                    'T1extensionAttribute2'
                    'T1extensionAttribute3'
                    'T1extensionAttribute4'
                    'T1extensionAttribute5'
                    'T1extensionAttribute6'
                    'T1extensionAttribute7'
                    'T1extensionAttribute8'
                    'T1extensionAttribute9'
                    'T1extensionAttribute10'
                    'T1extensionAttribute11'
                    'T1extensionAttribute12'
                    'T1extensionAttribute13'
                    'T1extensionAttribute14'
                    'T1extensionAttribute15'

                    'T2displayName'
                    'T2userPrincipalName'
                    'T2id'
                    'T2accountEnabled'
                    'T2createdDateTime'
                    'T2deletedDateTime'
                    'T2mail'
                    'T2lastSignInDateTime'
                    'T2lastNonInteractiveSignInDateTime'
                    'T2lastSuccessfulSignInDateTime'
                    'T2extensionAttribute1'
                    'T2extensionAttribute2'
                    'T2extensionAttribute3'
                    'T2extensionAttribute4'
                    'T2extensionAttribute5'
                    'T2extensionAttribute6'
                    'T2extensionAttribute7'
                    'T2extensionAttribute8'
                    'T2extensionAttribute9'
                    'T2extensionAttribute10'
                    'T2extensionAttribute11'
                    'T2extensionAttribute12'
                    'T2extensionAttribute13'
                    'T2extensionAttribute14'
                    'T2extensionAttribute15'
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
            $baseUri + '/' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '_Get-PrimaryAccountsByCloudAdminAccount.csv' + $uri.Query
        }
    )
    return
}

if ($OutText) { if ($return.Count -eq 0) { return 'No referenced primary user accounts found.' }; $return.userPrincipalName; return }

if ($return.Count -eq 0) {
    Write-Information 'No referenced primary user accounts found.' -InformationAction Continue
}

return $return
