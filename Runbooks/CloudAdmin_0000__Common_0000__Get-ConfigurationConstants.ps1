<#PSScriptInfo
.VERSION 1.2.0
.GUID 42b14e9d-de1d-4a82-ae38-9d8c33dd56fe
.AUTHOR Julian Pawlowski
.COMPANYNAME Workoho GmbH
.COPYRIGHT © 2024 Workoho GmbH
.TAGS
.LICENSEURI https://github.com/workoho/Entra-Tiering-Security-Model/blob/main/LICENSE.txt
.PROJECTURI https://github.com/workoho/Entra-Tiering-Security-Model
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES https://github.com/workoho/AzAuto-Common-Runbook-FW
.RELEASENOTES
    Version 1.2.0 (2024-04-15)
    - add configuration variable AV_CloudAdmin_InternalReferenceAccountLastSignInMinDaysBefore
    - add configuration variable AV_CloudAdmin_ExternalReferenceAccountLastSignInMinDaysBefore
    - add configuration variable EmployeeLeaveDateTimeMinDaysBefore
#>

<#
.SYNOPSIS
    Returns an array of Constants that are shared between all Cloud Administrator scripts.

.DESCRIPTION
    These constants are transformed using Common_0000__Convert-PSEnvToPSScriptVariable.ps1.
    Values come from local environment variables and are validated against the Regex or Type property,
    otherwise a default value is used.
    Script variables that are already set (e.g. via script parameters) may take higher priority using
    the respectScriptParameter property.

    In Azure Automation sandbox, environment variables are synchronzed with Azure Automation Variables
    before. See Common_0002__Import-AzAutomationVariableToPSEnv.ps1 for more details.

    That way, flexible configuration can be provided with easy control as part of the Azure Automation Account.
    Also, script runtime parameters can be reduced to the absolute minimum to improve security.

.NOTES
    CUSTOM CONFIGURATION SETTINGS
    =============================

    Variables for custom configuration settings, either from $env:<VariableName>,
    or Azure Automation Account Variables, whose will automatically be published in $env when running in Azure Automation.

    ********************************************************************************************************
    * Please note that <Tier> in the variable name must be replaced by the intended Tier level 0, 1, or 2. *
    * For example: AV_CloudAdminTier0_GroupId, AV_CloudAdminTier1_GroupId, AV_CloudAdminTier2_GroupId      *
    ********************************************************************************************************

    AV_CloudAdmin_RestrictedAdminUnitId - [String] - Default Value: $null
        ...

    AV_CloudAdmin_AccountTypeExtensionAttribute - [Integer] - Default Value: 15
        Save user account type information in this extension attribute. Content from the referral user will be copied and the Cloud Administrator
        information is added either as prefix or suffix (see AV_CloudAdminTier<Tier>_ExtensionAttribute* settings below).

    AV_CloudAdmin_AccountTypeEmployeeType - [Boolean] - Default Value: $true
        ...

    AV_CloudAdmin_ReferenceExtensionAttribute - [Integer] - Default Value: 14
        ...

    AV_CloudAdmin_ReferenceManager - [Boolean] - Default Value: $false
        ...

    AV_CloudAdmin_Webhook - [String] - Default Value: $null
        Send return data in JSON format as POST to this webhook URL.

    AV_CloudAdminTier0_AccountRestrictedAdminUnitId
        ...

    AV_CloudAdminTier<Tier>_AccountAdminUnitId
        Tier 1 and 2 only, see AV_CloudAdminTier0_AccountRestrictedAdminUnitId for Tier 0.

    AV_CloudAdminTier<Tier>_UserPhotoUrl - [String] - Default Value: <empty>
        Default value for script parameter UserPhotoUrl. If no parameter was provided, this value will be used instead.
        If no value was provided at all, the tenant's square logo will be used.

    AV_CloudAdminTier<Tier>_LicenseSkuPartNumber - [String] - Default Value: EXCHANGEDESKLESS
        License assigned to the dedicated admin user account. The license SKU part number must contain an Exchange Online service plan to generate a mailbox
        for the user (see https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference).
        Multiple licenses may be assigned using a whitespace delimiter.
        For the license containing the Exchange Online service plan, only that service plan is enabled for the user, any other service plan within that license will be disabled.
        If GroupId is also provided, group-based licensing is implied and Exchange Online service plan activation will only be monitored before continuing.

    AV_CloudAdminTier<Tier>_GroupId - [String] - Default Value: <empty>
        Entra Group Object ID where the user shall be added. If the group is dynamic, group membership update will only be monitored before continuing.

    AV_CloudAdminTier<Tier>_DedicatedAccount - [String] - Default Value: 'Require' for Tier 0, 'Optional' for Tier 1, 'None' for Tier 2
        ...

    AV_CloudAdminTier<Tier>_AccountDomain - [String] - Default Value: onmicrosoft.com
        ...

    AV_CloudAdminTier<Tier>_AccountTypeEmployeeTypePrefix - [String] - Default Value:
        ...

    AV_CloudAdminTier<Tier>_AccountTypeEmployeeTypePrefixSeparator - [String] - Default Value:
        ...

    AV_CloudAdminTier<Tier>_AccountTypeEmployeeTypeSuffix - [String] - Default Value:
        ...

    AV_CloudAdminTier<Tier>_AccountTypeEmployeeTypeSuffixSeparator - [String] - Default Value:
        ...

    AV_CloudAdminTier<Tier>_AccountTypeExtensionAttributePrefix - [String] - Default Value:
        ...

    AV_CloudAdminTier<Tier>_AccountTypeExtensionAttributePrefixSeparator - [String] - Default Value:
        ...

    AV_CloudAdminTier<Tier>_AccountTypeExtensionAttributeSuffix - [String] - Default Value:
        ...

    AV_CloudAdminTier<Tier>_AccountTypeExtensionAttributeSuffixSeparator - [String] - Default Value:
        ...

    AV_CloudAdminTier<Tier>_UserDisplayNamePrefix - [String] - Default Value:
        ...

    AV_CloudAdminTier<Tier>_UserDisplayNamePrefixSeparator - [String] - Default Value:
        ...

    AV_CloudAdminTier<Tier>_UserDisplayNamePrefixInsertPoint - [String] - Default Value:
        ...

    AV_CloudAdminTier<Tier>_UserDisplayNameSuffix - [String] - Default Value:
        ...

    AV_CloudAdminTier<Tier>_UserDisplayNameSuffixSeparator - [String] - Default Value:
        ...

    AV_CloudAdminTier<Tier>_UserDisplayNameSuffixInsertPoint - [String] - Default Value:
        ...

    AV_CloudAdminTier<Tier>_GivenNamePrefix - [String] - Default Value:
        ...

    AV_CloudAdminTier<Tier>_GivenNamePrefixSeparator - [String] - Default Value:
        ...

    AV_CloudAdminTier<Tier>_GivenNameSuffix - [String] - Default Value:
        ...

    AV_CloudAdminTier<Tier>_GivenNameSuffixSeparator - [String] - Default Value:
        ...

    AV_CloudAdminTier<Tier>_UserPrincipalNameUsesSamAccountName - [Boolean] - Default Value: $false
        ...

    AV_CloudAdminTier<Tier>_UserPrincipalNamePrefix - [String] - Default Value:
        ...

    AV_CloudAdminTier<Tier>_UserPrincipalNamePrefixSeparator - [String] - Default Value:
        ...

    AV_CloudAdminTier<Tier>_UserPrincipalNameSuffix - [String] - Default Value:
        ...

    AV_CloudAdminTier<Tier>_UserPrincipalNameSuffixSeparator - [String] - Default Value:
        ...

#>

[OutputType([array])]
param()

if (-Not $PSCommandPath) { Write-Error 'This runbook is used by other runbooks and must not be run directly.' -ErrorAction Stop; exit }
Write-Verbose "---START of $((Get-Item $PSCommandPath).Name), $((Test-ScriptFileInfo $PSCommandPath | Select-Object -Property Version, Guid | & { process{$_.PSObject.Properties | & { process{$_.Name + ': ' + $_.Value} }} }) -join ', ') ---"

$Constants = [array] @(
    #region General Constants
    @{
        sourceName    = "AV_CloudAdmin_RestrictedAdminUnitId"
        mapToVariable = 'CloudAdminRestrictedAdminUnitId'
        defaultValue  = $null
        Regex         = '^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$'
    }
    @{
        sourceName    = "AV_CloudAdmin_AccountTypeExtensionAttribute"
        mapToVariable = 'AccountTypeExtensionAttribute'
        defaultValue  = 15
        Regex         = '^([1-9]|1[012345])$'
    }
    @{
        sourceName    = "AV_CloudAdmin_AccountTypeExtensionAttributeOverwrite"
        mapToVariable = 'AccountTypeExtensionAttributeOverwrite'
        defaultValue  = $false
    }
    @{
        sourceName    = "AV_CloudAdmin_AccountTypeEmployeeType"
        mapToVariable = 'AccountTypeEmployeeType'
        defaultValue  = $true
    }
    @{
        sourceName    = "AV_CloudAdmin_ReferenceExtensionAttribute"
        mapToVariable = 'ReferenceExtensionAttribute'
        defaultValue  = 14
        Regex         = '^([1-9]|1[012345])$'
    }
    @{
        sourceName    = "AV_CloudAdmin_ReferenceExtensionAttributeOverwrite"
        mapToVariable = 'ReferenceExtensionAttributeOverwrite'
        defaultValue  = $false
    }
    @{
        sourceName    = "AV_CloudAdmin_ReferenceManager"
        mapToVariable = 'ReferenceManager'
        defaultValue  = $false
    }
    @{
        sourceName    = "AV_CloudAdmin_InternalReferenceAccountLastSignInMinDaysBefore"
        mapToVariable = 'InternalReferenceAccountLastSignInMinDaysBefore'
        defaultValue  = '14'
        Regex         = '^-?\d+$'
    }
    @{
        sourceName    = "AV_CloudAdmin_ExternalReferenceAccountLastSignInMinDaysBefore"
        mapToVariable = 'ExternalReferenceAccountLastSignInMinDaysBefore'
        defaultValue  = '30'
        Regex         = '^-?\d+$'
    }
    @{
        sourceName    = "AV_CloudAdmin_EmployeeLeaveDateTimeMinDaysBefore"
        mapToVariable = 'EmployeeLeaveDateTimeMinDaysBefore'
        defaultValue  = '45'
        Regex         = '^-?\d+$'
    }
    @{
        sourceName    = "AV_CloudAdmin_Webhook"
        mapToVariable = 'Webhook'
        defaultValue  = $null
        Regex         = '^https:\/\/.+$'
    }
    @{
        sourceName    = "AV_CloudAdmin_WelcomeMailLogo"
        mapToVariable = 'WelcomeMailLogo'
        defaultValue  = $null
        Regex         = '^((?:data|https?):.+)$'
    }
    @{
        sourceName    = "AV_CloudAdmin_WelcomeMailSender"
        mapToVariable = 'WelcomeMailSender'
        defaultValue  = $null
        Regex         = '^[^\s]+@[^\s]+\.[^\s]+$|^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$'
    }
    #endregion

    #region Tier 0 Constants
    @{
        sourceName    = "AV_CloudAdminTier0_AccountRestrictedAdminUnitId"
        mapToVariable = 'AccountRestrictedAdminUnitId_Tier0'
        defaultValue  = $null
        Regex         = '^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_LicenseGroupId"
        mapToVariable = 'LicenseGroupId_Tier0'
        defaultValue  = $null
        Regex         = '^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_LicenseSkuPartNumber"
        mapToVariable = 'LicenseSkuPartNumber_Tier0'
        defaultValue  = 'EXCHANGEDESKLESS'
        Regex         = '^[A-Z0-9][A-Z0-9_ ]+[A-Z0-9]$'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_GroupId"
        mapToVariable = 'GroupId_Tier0'
        defaultValue  = $null
        Regex         = '^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$'
    }
    @{
        sourceName             = "AV_CloudAdminTier0_UserPhotoUrl"
        respectScriptParameter = 'UserPhotoUrl'
        mapToVariable          = 'PhotoUrl_Tier0'
        defaultValue           = $null
        Regex                  = '^https:\/\/.+(?:\.png|\.jpg|\.jpeg|\?.+)$'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_DedicatedAccount"
        mapToVariable = 'DedicatedAccount_Tier0'
        defaultValue  = 'Require'
        Regex         = '^(?:Require|Optional|None)$'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_AllowedGuestOrExternalForDedicatedAccount"
        mapToVariable = 'AllowedGuestOrExternalForDedicatedAccount_Tier0'
        defaultValue  = $false
    }
    @{
        sourceName    = "AV_CloudAdminTier0_AllowedGuestOrExternalUserTypes"
        mapToVariable = 'AllowedGuestOrExternalUserTypes_Tier0'
        defaultValue  = $null
        Regex         = '(?:internalGuest|b2bCollaborationGuest|b2bCollaborationMember|otherExternalUser)(\s|$)+'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_AllowFacebookAccount"
        mapToVariable = 'AllowFacebookAccount_Tier0'
        defaultValue  = $false
    }
    @{
        sourceName    = "AV_CloudAdminTier0_AllowGoogleAccount"
        mapToVariable = 'AllowGoogleAccount_Tier0'
        defaultValue  = $false
    }
    @{
        sourceName    = "AV_CloudAdminTier0_AllowMicrosoftAccount"
        mapToVariable = 'AllowMicrosoftAccount_Tier0'
        defaultValue  = $false
    }
    @{
        sourceName    = "AV_CloudAdminTier0_AllowExternalEntraAccount"
        mapToVariable = 'AllowExternalEntraAccount_Tier0'
        defaultValue  = $false
    }
    @{
        sourceName    = "AV_CloudAdminTier0_AllowFederatedAccount"
        mapToVariable = 'AllowFederatedAccount_Tier0'
        defaultValue  = $false
    }
    @{
        sourceName    = "AV_CloudAdminTier0_AccountDomain"
        mapToVariable = 'AccountDomain_Tier0'
        defaultValue  = 'onmicrosoft.com'
        Regex         = '^(?=^.{1,253}$)(([a-z\d]([a-z\d-]{0,62}[a-z\d])*[\.]){1,3}[a-z]{1,61})$'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_AllowSameDomainForReferralUser"
        mapToVariable = 'AllowSameDomainForReferralUser_Tier0'
        defaultValue  = $false
    }
    @{
        sourceName    = "AV_CloudAdminTier0_AccountTypeEmployeeTypePrefix"
        mapToVariable = 'AccountTypeEmployeeTypePrefix_Tier0'
        defaultValue  = 'Tier 0 Cloud Administrator'
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_AccountTypeEmployeeTypePrefixSeparator"
        mapToVariable = 'AccountTypeEmployeeTypePrefixSeparator_Tier0'
        defaultValue  = ' ('
        Regex         = '^.{1,2}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_AccountTypeEmployeeTypeSuffix"
        mapToVariable = 'AccountTypeEmployeeTypeSuffix_Tier0'
        defaultValue  = ')'
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_AccountTypeEmployeeTypeSuffixSeparator"
        mapToVariable = 'AccountTypeEmployeeTypeSuffixSeparator_Tier0'
        defaultValue  = ''
        Regex         = '^.{1,2}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_AccountTypeExtensionAttributePrefix"
        mapToVariable = 'AccountTypeExtensionAttributePrefix_Tier0'
        defaultValue  = 'A0C'
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_AccountTypeExtensionAttributePrefixSeparator"
        mapToVariable = 'AccountTypeExtensionAttributePrefixSeparator_Tier0'
        defaultValue  = '__'
        Regex         = '^.{1,2}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_AccountTypeExtensionAttributeSuffix"
        mapToVariable = 'AccountTypeExtensionAttributeSuffix_Tier0'
        defaultValue  = $null
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_AccountTypeExtensionAttributeSuffixSeparator"
        mapToVariable = 'AccountTypeExtensionAttributeSuffixSeparator_Tier0'
        defaultValue  = '__'
        Regex         = '^.{1,2}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_UserDisplayNamePrefix"
        mapToVariable = 'UserDisplayNamePrefix_Tier0'
        defaultValue  = $null
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_UserDisplayNamePrefixSeparator"
        mapToVariable = 'UserDisplayNamePrefixSeparator_Tier0'
        defaultValue  = '-'
        Regex         = '^.{1,2}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_UserDisplayNamePrefixInsertPoint"
        mapToVariable = 'UserDisplayNamePrefixInsertPoint_Tier0'
        defaultValue  = $null
        Regex         = '.+'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_UserDisplayNameSuffix"
        mapToVariable = 'UserDisplayNameSuffix_Tier0'
        defaultValue  = '(A0C)'
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_UserDisplayNameSuffixSeparator"
        mapToVariable = 'UserDisplayNameSuffixSeparator_Tier0'
        defaultValue  = ' '
        Regex         = '^.{1,2}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_UserDisplayNameSuffixInsertPoint"
        mapToVariable = 'UserDisplayNameSuffixInsertPoint_Tier0'
        defaultValue  = '( \([^\(\)]+\)\s*$| \[[^\[\]]+\]\s*$)'
        Regex         = '.+'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_GivenNamePrefix"
        mapToVariable = 'GivenNamePrefix_Tier0'
        defaultValue  = 'A0C'
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_GivenNamePrefixSeparator"
        mapToVariable = 'GivenNamePrefixSeparator_Tier0'
        defaultValue  = '-'
        Regex         = '^.{1,2}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_GivenNameSuffix"
        mapToVariable = 'GivenNameSuffix_Tier0'
        defaultValue  = $null
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_GivenNameSuffixSeparator"
        mapToVariable = 'GivenNameSuffixSeparator_Tier0'
        defaultValue  = '-'
        Regex         = '^.{1,2}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_UserPrincipalNameUsesSamAccountName"
        mapToVariable = 'UserPrincipalNameUsesSamAccountName_Tier0'
        defaultValue  = $false
    }
    @{
        sourceName    = "AV_CloudAdminTier0_UserPrincipalNamePrefix"
        mapToVariable = 'UserPrincipalNamePrefix_Tier0'
        defaultValue  = 'A0C'
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_UserPrincipalNamePrefixSeparator"
        mapToVariable = 'UserPrincipalNamePrefixSeparator_Tier0'
        defaultValue  = '-'
        Regex         = '^.{1,2}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_UserPrincipalNameSuffix"
        mapToVariable = 'UserPrincipalNameSuffix_Tier0'
        defaultValue  = $null
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier0_UserPrincipalNameSuffixSeparator"
        mapToVariable = 'UserPrincipalNameSuffixSeparator_Tier0'
        defaultValue  = '-'
        Regex         = '^.{1,2}$'
    }
    #endregion

    #region Tier 1 Constants
    @{
        sourceName    = "AV_CloudAdminTier1_AccountAdminUnitId"
        mapToVariable = 'AccountAdminUnitId_Tier1'
        defaultValue  = $null
        Regex         = '^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_LicenseGroupId"
        mapToVariable = 'LicenseGroupId_Tier1'
        defaultValue  = $null
        Regex         = '^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_LicenseSkuPartNumber"
        mapToVariable = 'LicenseSkuPartNumber_Tier1'
        defaultValue  = 'EXCHANGEDESKLESS'
        Regex         = '^[A-Z0-9][A-Z0-9_ ]+[A-Z0-9]$'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_GroupId"
        mapToVariable = 'GroupId_Tier1'
        defaultValue  = $null
        Regex         = '^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$'
    }
    @{
        sourceName             = "AV_CloudAdminTier1_UserPhotoUrl"
        respectScriptParameter = 'UserPhotoUrl'
        mapToVariable          = 'PhotoUrl_Tier1'
        defaultValue           = $null
        Regex                  = '^https:\/\/.+(?:\.png|\.jpg|\.jpeg|\?.+)$'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_DedicatedAccount"
        mapToVariable = 'DedicatedAccount_Tier1'
        defaultValue  = 'Optional'
        Regex         = '^(?:Require|Optional)$'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_AllowedGuestOrExternalForDedicatedAccount"
        mapToVariable = 'AllowedGuestOrExternalForDedicatedAccount_Tier1'
        defaultValue  = $false
    }
    @{
        sourceName    = "AV_CloudAdminTier1_AllowedGuestOrExternalUserTypes"
        mapToVariable = 'AllowedGuestOrExternalUserTypes_Tier1'
        defaultValue  = $null
        Regex         = '(?:internalGuest|b2bCollaborationGuest|b2bCollaborationMember|otherExternalUser)(\s|$)+'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_AllowFacebookAccount"
        mapToVariable = 'AllowFacebookAccount_Tier1'
        defaultValue  = $false
    }
    @{
        sourceName    = "AV_CloudAdminTier1_AllowGoogleAccount"
        mapToVariable = 'AllowGoogleAccount_Tier1'
        defaultValue  = $false
    }
    @{
        sourceName    = "AV_CloudAdminTier1_AllowMicrosoftAccount"
        mapToVariable = 'AllowMicrosoftAccount_Tier1'
        defaultValue  = $false
    }
    @{
        sourceName    = "AV_CloudAdminTier1_AllowExternalEntraAccount"
        mapToVariable = 'AllowExternalEntraAccount_Tier1'
        defaultValue  = $false
    }
    @{
        sourceName    = "AV_CloudAdminTier1_AllowFederatedAccount"
        mapToVariable = 'AllowFederatedAccount_Tier1'
        defaultValue  = $false
    }
    @{
        sourceName    = "AV_CloudAdminTier1_AccountDomain"
        mapToVariable = 'AccountDomain_Tier1'
        defaultValue  = 'onmicrosoft.com'
        Regex         = '^(?=^.{1,253}$)(([a-z\d]([a-z\d-]{0,62}[a-z\d])*[\.]){1,3}[a-z]{1,61})$'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_AllowSameDomainForReferralUser"
        mapToVariable = 'AllowSameDomainForReferralUser_Tier1'
        defaultValue  = $false
    }
    @{
        sourceName    = "AV_CloudAdminTier1_AccountTypeEmployeeTypePrefix"
        mapToVariable = 'AccountTypeEmployeeTypePrefix_Tier1'
        defaultValue  = 'Tier 1 Cloud Administrator'
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_AccountTypeEmployeeTypePrefixSeparator"
        mapToVariable = 'AccountTypeEmployeeTypePrefixSeparator_Tier1'
        defaultValue  = ' ('
        Regex         = '^.{1,2}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_AccountTypeEmployeeTypeSuffix"
        mapToVariable = 'AccountTypeEmployeeTypeSuffix_Tier1'
        defaultValue  = ')'
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_AccountTypeEmployeeTypeSuffixSeparator"
        mapToVariable = 'AccountTypeEmployeeTypeSuffixSeparator_Tier1'
        defaultValue  = ''
        Regex         = '^.{1,2}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_AccountTypeExtensionAttributePrefix"
        mapToVariable = 'AccountTypeExtensionAttributePrefix_Tier1'
        defaultValue  = 'A1C'
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_AccountTypeExtensionAttributePrefixSeparator"
        mapToVariable = 'AccountTypeExtensionAttributePrefixSeparator_Tier1'
        defaultValue  = '__'
        Regex         = '^.{1,2}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_AccountTypeExtensionAttributeSuffix"
        mapToVariable = 'AccountTypeExtensionAttributeSuffix_Tier1'
        defaultValue  = $null
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_AccountTypeExtensionAttributeSuffixSeparator"
        mapToVariable = 'AccountTypeExtensionAttributeSuffixSeparator_Tier1'
        defaultValue  = '__'
        Regex         = '^.{1,2}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_UserDisplayNamePrefix"
        mapToVariable = 'UserDisplayNamePrefix_Tier1'
        defaultValue  = $null
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_UserDisplayNamePrefixSeparator"
        mapToVariable = 'UserDisplayNamePrefixSeparator_Tier1'
        defaultValue  = '-'
        Regex         = '^.{1,2}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_UserDisplayNamePrefixInsertPoint"
        mapToVariable = 'UserDisplayNamePrefixInsertPoint_Tier1'
        defaultValue  = $null
        Regex         = '.+'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_UserDisplayNameSuffix"
        mapToVariable = 'UserDisplayNameSuffix_Tier1'
        defaultValue  = '(A1C)'
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_UserDisplayNameSuffixSeparator"
        mapToVariable = 'UserDisplayNameSuffixSeparator_Tier1'
        defaultValue  = ' '
        Regex         = '^.{1,2}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_UserDisplayNameSuffixInsertPoint"
        mapToVariable = 'UserDisplayNameSuffixInsertPoint_Tier1'
        defaultValue  = '( \([^\(\)]+\)\s*$| \[[^\[\]]+\]\s*$)'
        Regex         = '.+'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_GivenNamePrefix"
        mapToVariable = 'GivenNamePrefix_Tier1'
        defaultValue  = 'A1C'
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_GivenNamePrefixSeparator"
        mapToVariable = 'GivenNamePrefixSeparator_Tier1'
        defaultValue  = '-'
        Regex         = '^.{1,2}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_GivenNameSuffix"
        mapToVariable = 'GivenNameSuffix_Tier1'
        defaultValue  = $null
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_GivenNameSuffixSeparator"
        mapToVariable = 'GivenNameSuffixSeparator_Tier1'
        defaultValue  = '-'
        Regex         = '^.{1,2}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_UserPrincipalNameUsesSamAccountName"
        mapToVariable = 'UserPrincipalNameUsesSamAccountName_Tier1'
        defaultValue  = $false
    }
    @{
        sourceName    = "AV_CloudAdminTier1_UserPrincipalNamePrefix"
        mapToVariable = 'UserPrincipalNamePrefix_Tier1'
        defaultValue  = 'A1C'
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_UserPrincipalNamePrefixSeparator"
        mapToVariable = 'UserPrincipalNamePrefixSeparator_Tier1'
        defaultValue  = '-'
        Regex         = '^.{1,2}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_UserPrincipalNameSuffix"
        mapToVariable = 'UserPrincipalNameSuffix_Tier1'
        defaultValue  = $null
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier1_UserPrincipalNameSuffixSeparator"
        mapToVariable = 'UserPrincipalNameSuffixSeparator_Tier1'
        defaultValue  = '-'
        Regex         = '^.{1,2}$'
    }
    #endregion

    #region Tier 2 Constants
    @{
        sourceName    = "AV_CloudAdminTier2_AccountAdminUnitId"
        mapToVariable = 'AccountAdminUnitId_Tier2'
        defaultValue  = $null
        Regex         = '^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_LicenseGroupId"
        mapToVariable = 'LicenseGroupId_Tier2'
        defaultValue  = $null
        Regex         = '^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_LicenseSkuPartNumber"
        mapToVariable = 'LicenseSkuPartNumber_Tier2'
        defaultValue  = ''
        Regex         = '^[A-Z0-9][A-Z0-9_ ]+[A-Z0-9]$'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_GroupId"
        mapToVariable = 'GroupId_Tier2'
        defaultValue  = $null
        Regex         = '^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$'
    }
    @{
        sourceName             = "AV_CloudAdminTier2_UserPhotoUrl"
        respectScriptParameter = 'UserPhotoUrl'
        mapToVariable          = 'PhotoUrl_Tier2'
        defaultValue           = $null
        Regex                  = '^https:\/\/.+(?:\.png|\.jpg|\.jpeg|\?.+)$'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_DedicatedAccount"
        mapToVariable = 'DedicatedAccount_Tier2'
        defaultValue  = 'Optional'
        Regex         = '^(?:Require|Optional|None)$'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_AllowedGuestOrExternalForDedicatedAccount"
        mapToVariable = 'AllowedGuestOrExternalForDedicatedAccount_Tier2'
        defaultValue  = $false
    }
    @{
        sourceName    = "AV_CloudAdminTier2_AllowedGuestOrExternalUserTypes"
        mapToVariable = 'AllowedGuestOrExternalUserTypes_Tier2'
        defaultValue  = 'internalGuest b2bCollaborationGuest b2bCollaborationMember'
        Regex         = '(?:internalGuest|b2bCollaborationGuest|b2bCollaborationMember|otherExternalUser)(\s|$)+'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_AllowFacebookAccount"
        mapToVariable = 'AllowFacebookAccount_Tier2'
        defaultValue  = $false
    }
    @{
        sourceName    = "AV_CloudAdminTier2_AllowGoogleAccount"
        mapToVariable = 'AllowGoogleAccount_Tier2'
        defaultValue  = $false
    }
    @{
        sourceName    = "AV_CloudAdminTier2_AllowMicrosoftAccount"
        mapToVariable = 'AllowMicrosoftAccount_Tier2'
        defaultValue  = $false
    }
    @{
        sourceName    = "AV_CloudAdminTier2_AllowExternalEntraAccount"
        mapToVariable = 'AllowExternalEntraAccount_Tier2'
        defaultValue  = $true
    }
    @{
        sourceName    = "AV_CloudAdminTier2_AllowFederatedAccount"
        mapToVariable = 'AllowFederatedAccount_Tier2'
        defaultValue  = $false
    }
    @{
        sourceName    = "AV_CloudAdminTier2_AccountDomain"
        mapToVariable = 'AccountDomain_Tier2'
        defaultValue  = 'onmicrosoft.com'
        Regex         = '^(?=^.{1,253}$)(([a-z\d]([a-z\d-]{0,62}[a-z\d])*[\.]){1,3}[a-z]{1,61})$'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_AllowSameDomainForReferralUser"
        mapToVariable = 'AllowSameDomainForReferralUser_Tier2'
        defaultValue  = $false
    }
    @{
        sourceName    = "AV_CloudAdminTier2_AccountTypeEmployeeTypePrefix"
        mapToVariable = 'AccountTypeEmployeeTypePrefix_Tier2'
        defaultValue  = 'Tier 2 Cloud Administrator'
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_AccountTypeEmployeeTypePrefixSeparator"
        mapToVariable = 'AccountTypeEmployeeTypePrefixSeparator_Tier2'
        defaultValue  = ' ('
        Regex         = '^.{1,2}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_AccountTypeEmployeeTypeSuffix"
        mapToVariable = 'AccountTypeEmployeeTypeSuffix_Tier2'
        defaultValue  = ')'
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_AccountTypeEmployeeTypeSuffixSeparator"
        mapToVariable = 'AccountTypeEmployeeTypeSuffixSeparator_Tier2'
        defaultValue  = ''
        Regex         = '^.{1,2}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_AccountTypeExtensionAttributePrefix"
        mapToVariable = 'AccountTypeExtensionAttributePrefix_Tier2'
        defaultValue  = 'A2C'
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_AccountTypeExtensionAttributePrefixSeparator"
        mapToVariable = 'AccountTypeExtensionAttributePrefixSeparator_Tier2'
        defaultValue  = '__'
        Regex         = '^.{1,2}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_AccountTypeExtensionAttributeSuffix"
        mapToVariable = 'AccountTypeExtensionAttributeSuffix_Tier2'
        defaultValue  = $null
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_AccountTypeExtensionAttributeSuffixSeparator"
        mapToVariable = 'AccountTypeExtensionAttributeSuffixSeparator_Tier2'
        defaultValue  = '__'
        Regex         = '^.{1,2}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_UserDisplayNamePrefix"
        mapToVariable = 'UserDisplayNamePrefix_Tier2'
        defaultValue  = $null
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_UserDisplayNamePrefixSeparator"
        mapToVariable = 'UserDisplayNamePrefixSeparator_Tier2'
        defaultValue  = '-'
        Regex         = '^.{1,2}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_UserDisplayNamePrefixInsertPoint"
        mapToVariable = 'UserDisplayNamePrefixInsertPoint_Tier2'
        defaultValue  = $null
        Regex         = '.+'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_UserDisplayNameSuffix"
        mapToVariable = 'UserDisplayNameSuffix_Tier2'
        defaultValue  = '(A2C)'
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_UserDisplayNameSuffixSeparator"
        mapToVariable = 'UserDisplayNameSuffixSeparator_Tier2'
        defaultValue  = ' '
        Regex         = '^.{1,2}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_UserDisplayNameSuffixInsertPoint"
        mapToVariable = 'UserDisplayNameSuffixInsertPoint_Tier2'
        defaultValue  = '( \([^\(\)]+\)\s*$| \[[^\[\]]+\]\s*$)'
        Regex         = '.+'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_GivenNamePrefix"
        mapToVariable = 'GivenNamePrefix_Tier2'
        defaultValue  = 'A2C'
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_GivenNamePrefixSeparator"
        mapToVariable = 'GivenNamePrefixSeparator_Tier2'
        defaultValue  = '-'
        Regex         = '^.{1,2}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_GivenNameSuffix"
        mapToVariable = 'GivenNameSuffix_Tier2'
        defaultValue  = $null
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_GivenNameSuffixSeparator"
        mapToVariable = 'GivenNameSuffixSeparator_Tier2'
        defaultValue  = '-'
        Regex         = '^.{1,2}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_UserPrincipalNameUsesSamAccountName"
        mapToVariable = 'UserPrincipalNameUsesSamAccountName_Tier2'
        defaultValue  = $false
    }
    @{
        sourceName    = "AV_CloudAdminTier2_UserPrincipalNamePrefix"
        mapToVariable = 'UserPrincipalNamePrefix_Tier2'
        defaultValue  = 'A2C'
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_UserPrincipalNamePrefixSeparator"
        mapToVariable = 'UserPrincipalNamePrefixSeparator_Tier2'
        defaultValue  = '-'
        Regex         = '^.{1,2}$'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_UserPrincipalNameSuffix"
        mapToVariable = 'UserPrincipalNameSuffix_Tier2'
        defaultValue  = $null
        Regex         = '^[^\s].*[^\s]$|^.$'
    }
    @{
        sourceName    = "AV_CloudAdminTier2_UserPrincipalNameSuffixSeparator"
        mapToVariable = 'UserPrincipalNameSuffixSeparator_Tier2'
        defaultValue  = '-'
        Regex         = '^.{1,2}$'
    }
    #endregion
)

Write-Verbose "-----END of $((Get-Item $PSCommandPath).Name) ---"
return $Constants
