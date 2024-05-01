@{
    ModuleVersion = '1.2.1'     # This is the version of the framework you want to use. Only used if GitReference is set to 'ModuleVersion'.
    Author        = 'Azure Automation Common Runbook Framework'
    Description   = 'Main configuration file child project using the Azure Automation Common Runbook Framework.'
    PrivateData   = @{
        # GitReference can be one of the following:
        # 1. 'ModuleVersion' (see value above in the ModuleVersion key of this file)
        # 2. 'LatestRelease' (ignores ModuleVersion but detects latest release version automatically as it is released)
        # 3. 'latest' (will go to the latest commit of the branch to give you the latest code, but may be unstable)
        # 4. A Git commit hash or branch name (if you know what you're doing and want to pin to a specific commit or branch)
        GitReference                 = 'ModuleVersion'

        # GitRepositoryUrl must be a valid Git repository URL. You likely don't want to change this unless you're forking the framework.
        GitRepositoryUrl             = 'https://github.com/workoho/AzAuto-Common-Runbook-FW.git'

        # Files belonging to the framework are usually symlinked to the child project to keep them up to date.
        # On Windows, this requires SeCreateSymbolicLinkPrivilege to be enabled, or manually running the Update-AzAutoFWProjectRunbooks.ps1 script as an administrator.
        # If you would like to enforce using symlinks on Windows in any case, set this to $true.
        EnforceSymlink               = $false

        # In rare cases, common runbooks may be copied instead of using symbolic links.
        # If you set $EnforceSymlink to $true but still would like to copy the runbooks, set this to $true.
        CopyRunbooks                 = $false

        # If you enabled CopyRunbooks, or Windows is not enabled for symlinks, common runbooks are automatically updated when the
        # Update-AzAutoFWProjectRunbooks.ps1 script is run.
        # In case you want to update them manually, you can set this to $true. That way, you may keep changes you made to the runbooks.
        # Please note that you will need to manually keep track of updates to the common runbooks and apply them yourself.
        # We recommend that you instead write your own runbooks that call the common runbooks, so that you can update the common runbooks
        # automatically.
        UpdateRunbooksManually       = $false

        # The following Automation Variables are used by runbooks of the automation project.
        # SECURITY NOTE: Do _NOT_ set any critical values here. Use the AzAutoFWProject.local.psd1 file instead if needed.
        AutomationVariable           = @(
            #region Cloud Administrator Tiering Basic Configuration
            @{
                Name             = 'AV_CloudAdmin_RestrictedAdminUnitId'
                Value            = ''
                ValueReferenceTo = 'AdministrativeUnit.Groups.Id'   # Inherit the Id of the Administrative Unit defined below and overwrite the 'Value' property here
                Description      = 'The ID of the Entra ID Admin Unit that contains the Cloud Admin Tiering Groups.'
            }
            @{
                Name             = 'AV_CloudAdminTier0_GroupId'
                Value            = ''
                ValueReferenceTo = 'Group.AdminUsersT0.Id'   # Inherit the Id of the Group defined below and overwrite the 'Value' property here
                Description      = 'The ID of the Entra ID Group that contains all Cloud Admins of Tier 0.'
            }
            @{
                Name             = 'AV_CloudAdminTier1_GroupId'
                Value            = ''
                ValueReferenceTo = 'Group.AdminUsersT1.Id'   # Inherit the Id of the Group defined below and overwrite the 'Value' property here
                Description      = 'The ID of the Entra ID Group that contains all Cloud Admins of Tier 1.'
            }
            @{
                Name             = 'AV_CloudAdminTier2_GroupId'
                Value            = ''
                ValueReferenceTo = 'Group.AdminUsersT2.Id'   # Inherit the Id of the Group defined below and overwrite the 'Value' property here
                Description      = 'The ID of the Entra ID Group that contains all Cloud Admins of Tier 2.'
            }
            #endregion

            #region Cloud Administrator Tier 0 Configuration
            @{
                Name             = 'AV_CloudAdminTier0_AccountRestrictedAdminUnitId'
                Value            = ''
                ValueReferenceTo = 'AdministrativeUnit.AdminUsersT0.Id'   # Inherit the Id of the Administrative Unit defined below and overwrite the 'Value' property here
                Description      = 'The ID of the Entra ID Admin Unit that contains the dedicated Cloud Admin Accounts of Tier 0.'
            }
            @{
                Name             = 'AV_CloudAdminTier0_LicenseGroupId'
                Value            = ''
                ValueReferenceTo = 'Group.AdminUsersT0License.Id'   # Inherit the Id of the Group defined below and overwrite the 'Value' property here
                Description      = 'The ID of the Entra ID Licensing Group that contains the dedicated Cloud Admin Accounts of Tier 0.'
            }
            @{
                Name             = 'AV_CloudAdminTier0_LicenseSkuPartNumber'
                Value            = ''
                ValueReferenceTo = 'Group.AdminUsersT0License.InitialLicenseAssignment[0].SkuPartNumber'   # Inherit the SkuPartNumber of the Group defined below and overwrite the 'Value' property here
                Description      = 'The SkuPartNumber of the license that we use for email forwarding in Exchange Online for dedicated Cloud Admin Accounts of Tier 0.'
            }
            # @{
            #     Name        = 'AV_CloudAdminTier0_UserPhotoUrl'
            #     Value       = ''
            #     Description = "The URL of the photo of the dedicated Cloud Admin Accounts of Tier 0. When left empty or set to '', no photo will be set. If you don't set this variable at all, the photo will be set to tenant branding square logo."
            # }
            #endregion

            #region Cloud Administrator Tier 1 Configuration
            @{
                Name             = 'AV_CloudAdminTier1_AccountAdminUnitId'
                Value            = ''
                ValueReferenceTo = 'AdministrativeUnit.AdminUsersT1.Id'   # Inherit the Id of the Administrative Unit defined below and overwrite the 'Value' property here
                Description      = 'The ID of the Entra ID Admin Unit that contains the dedicated Cloud Admin Accounts of Tier 1.'
            }
            @{
                Name             = 'AV_CloudAdminTier1_LicenseGroupId'
                Value            = ''
                ValueReferenceTo = 'Group.AdminUsersT1License.Id'   # Inherit the Id of the Group defined below and overwrite the 'Value' property here
                Description      = 'The ID of the Entra ID Licensing Group that contains the dedicated Cloud Admin Accounts of Tier 1.'
            }
            @{
                Name             = 'AV_CloudAdminTier1_LicenseSkuPartNumber'
                Value            = ''
                ValueReferenceTo = 'Group.AdminUsersT1License.InitialLicenseAssignment[0].SkuPartNumber'   # Inherit the SkuPartNumber of the Group defined below and overwrite the 'Value' property here
                Description      = 'The SkuPartNumber of the license that we use for email forwarding in Exchange Online for dedicated Cloud Admin Accounts of Tier 1.'
            }
            # @{
            #     Name        = 'AV_CloudAdminTier1_UserPhotoUrl'
            #     Value       = ''
            #     Description = "The URL of the photo of the dedicated Cloud Admin Accounts of Tier 1. When left empty or set to '', no photo will be set. If you don't set this variable at all, the photo will be set to tenant branding square logo."
            # }
            #endregion

            #region Cloud Administrator Tier 2 Configuration
            @{
                Name             = 'AV_CloudAdminTier2_AccountAdminUnitId'
                Value            = ''
                ValueReferenceTo = 'AdministrativeUnit.AdminUsersT2.Id'   # Inherit the Id of the Administrative Unit defined below and overwrite the 'Value' property here
                Description      = 'The ID of the Entra ID Admin Unit that contains the dedicated Cloud Admin Accounts of Tier 2.'
            }
            @{
                Name             = 'AV_CloudAdminTier2_LicenseGroupId'
                Value            = ''
                ValueReferenceTo = 'Group.AdminUsersT2License.Id'   # Inherit the Id of the Group defined below and overwrite the 'Value' property here
                Description      = 'The ID of the Entra ID Licensing Group that contains the dedicated Cloud Admin Accounts of Tier 2.'
            }
            @{
                Name             = 'AV_CloudAdminTier2_LicenseSkuPartNumber'
                Value            = ''
                ValueReferenceTo = 'Group.AdminUsersT2License.InitialLicenseAssignment[0].SkuPartNumber'   # Inherit the SkuPartNumber of the Group defined below and overwrite the 'Value' property here
                Description      = 'The SkuPartNumber of the license that we use for email forwarding in Exchange Online for dedicated Cloud Admin Accounts of Tier 2.'
            }
            # @{
            #     Name        = 'AV_CloudAdminTier2_UserPhotoUrl'
            #     Value       = ''
            #     Description = "The URL of the photo of the dedicated Cloud Admin Accounts of Tier 2. When left empty or set to '', no photo will be set. If you don't set this variable at all, the photo will be set to tenant branding square logo."
            # }
            #endregion
        )

        # Configure your Azure Automation Runtime Environments and packages to be installed.
        AutomationRuntimeEnvironment = @{

            # This is the system-generated Runtime Environment name for PowerShell 5.1.
            'PowerShell-5.1' = @{
                Runtime  = @{
                    Language = 'PowerShell'
                    Version  = '5.1'
                }

                Packages = @(
                    # Due to a bug in Azure Automation Runtime Environments, we must install at least
                    # one package via the old method into the default environment
                    # (which is not writeable via GUI anymore, but old API's still make it accessibile for us)
                    @{
                        Name    = 'Microsoft.Graph.Authentication'
                        Version = '2.16.0'
                    }
                )
            }

            # # This is the system-generated Runtime Environment name for PowerShell 7.2.
            # 'PowerShell-7.2'          = @{
            #     Description = ''
            #     Runtime     = @{
            #         Language = 'PowerShell'
            #         Version  = '7.2'
            #     }

            #     Packages    = @(
            #     )
            # }

            # This is a custom Runtime Environment name for PowerShell 5.1 with Az 8.0.0 and additional modules.
            # This is currently required as Az 11.2.0 does not work correctly in PowerShell 5.1 in Azure Automation.
            'CloudAdmin-V1'  = @{
                Description = 'Runtime environment for Cloud Administrator Tiering Automation Runbooks with Az 8.0.0 and additional modules.'
                Runtime     = @{
                    Language = 'PowerShell'
                    Version  = '5.1'    # We use PowerShell 5.1 here, as it is the only version that supports child runbooks at the time of writing.
                }

                Packages    = @(
                    @{
                        # This is the defaultPackage and must always be set.
                        Name      = 'Az'
                        Version   = '8.0.0'     # Note that version 11.2.0 currently does not work correctly in PowerShell 5.1 in Azure Automation
                        IsDefault = $true
                    }
                    @{
                        Name    = 'Microsoft.Graph.Authentication'
                        Version = '2.16.0'
                    }
                    @{
                        Name    = 'Microsoft.Graph.Identity.SignIns'
                        Version = '2.16.0'
                    }
                    @{
                        Name    = 'Microsoft.Graph.Identity.DirectoryManagement'
                        Version = '2.16.0'
                    }
                    @{
                        Name    = 'Microsoft.Graph.ChangeNotifications'
                        Version = '2.16.0'
                    }
                    @{
                        Name    = 'Microsoft.Graph.Users'
                        Version = '2.16.0'
                    }
                    @{
                        Name    = 'Microsoft.Graph.Users.Actions'
                        Version = '2.16.0'
                    }
                    @{
                        Name    = 'Microsoft.Graph.Users.Functions'
                        Version = '2.16.0'
                    }
                    @{
                        Name    = 'Microsoft.Graph.Groups'
                        Version = '2.16.0'
                    }
                    @{
                        Name    = 'Microsoft.Graph.Applications'
                        Version = '2.16.0'
                    }
                    @{
                        Name    = 'Microsoft.Graph.Beta.Identity.SignIns'
                        Version = '2.16.0'
                    }
                    @{
                        Name    = 'Microsoft.Graph.Beta.Identity.DirectoryManagement'
                        Version = '2.16.0'
                    }
                    @{
                        Name    = 'Microsoft.Graph.Beta.Users'
                        Version = '2.16.0'
                    }
                    @{
                        Name    = 'Microsoft.Graph.Beta.Users.Actions'
                        Version = '2.16.0'
                    }
                    @{
                        Name    = 'Microsoft.Graph.Beta.Users.Functions'
                        Version = '2.16.0'
                    }
                    @{
                        Name    = 'Microsoft.Graph.Beta.Groups'
                        Version = '2.16.0'
                    }
                    @{
                        Name    = 'Microsoft.Graph.Beta.Applications'
                        Version = '2.16.0'
                    }
                    @{
                        Name    = 'ExchangeOnlineManagement'
                        Version = '3.4.0'
                    }
                )
            }
        }

        # Configure your Azure Automation Runbooks to be uploaded.
        AutomationRunbook            = @{
            DefaultRuntimeEnvironment = @{
                PowerShell = 'CloudAdmin-V1'
            }
            Runbooks                  = @(
                # # EXAMPLE:
                # @{
                #     Name               = 'MyRunbook.ps1'
                #     RuntimeEnvironment = 'PowerShell-5.1'   # In case you want to use a different Runtime Environment
                # }
            )
        }

        # Configure Managed Identities for the Azure Automation Account.
        ManagedIdentity              = @(

            # For security reasons, you may also move this to the AzAutoFWProject.local.psd1 file.

            # This is the primary Managed Identity for the Azure Automation Account.
            @{
                Type           = 'SystemAssigned'  # 'SystemAssigned' or 'UserAssigned'

                # Azure role assignments for the Managed Identity.
                AzureRoles     = @{

                    # Scope 'self' means the Automation Account itself.
                    'self' = @(
                        @{
                            DisplayName      = 'Reader'                                # 'Reader' is the minimum required role for the Automation Account
                            RoleDefinitionId = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'  # RoleDefinitionId is optional, but recommended to ensure the correct role is assigned.
                            Justification    = 'Let the Managed Identity read its own properties and access its own resources.'
                        }
                        @{
                            DisplayName      = 'Automation Operator'                   # 'Automation Operator' is required to read sensitive information, like encrypted Automation Variables
                            RoleDefinitionId = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'  # RoleDefinitionId is optional, but recommended to ensure the correct role is assigned.
                            Justification    = 'Let the Managed Identity read sensitive information, like encrypted Automation Variables.'
                        }
                    )
                }

                # Directory role assignments for the Managed Identity.
                DirectoryRoles = @(
                    @{
                        DisplayName    = 'Reports Reader'
                        RoleTemplateId = '4a5d8f65-41da-4de4-8968-e035b65339cf'                 # RoleTemplateId is optional, but recommended to ensure the correct role is assigned.
                        Justification  = 'Read Sign-in logs for User Account Administration (e.g. last login date, etc.)'
                    }

                    # User Account Administration
                    @{
                        DisplayName    = 'Exchange Recipient Administrator'
                        RoleTemplateId = '31392ffb-586c-42d1-9346-e59415a2cc4e'                 # RoleTemplateId is optional, but recommended to ensure the correct role is assigned.
                        Justification  = 'Manage mailboxes of dedicated, cloud-native Cloud Administrator accounts in Tier 0, 1, and 2'
                    }
                    @{
                        DisplayName                   = 'Groups Administrator'
                        RoleTemplateId                = 'fdd7a751-b60b-444a-984c-02652fe8fa1c'    # RoleTemplateId is optional, but recommended to ensure the correct role is assigned.
                        AdministrativeUnitReferenceTo = 'AdministrativeUnit.Groups'               # reference to the Administrative Unit defined below to add the role
                        Justification                 = 'Manage groups for Privileged Cloud Administration in Tier 0, 1, and 2'
                    }
                    @{
                        DisplayName                   = 'License Administrator'
                        RoleTemplateId                = '4d6ac14f-3453-41d0-bef9-a3e0c569773a'    # RoleTemplateId is optional, but recommended to ensure the correct role is assigned.
                        AdministrativeUnitReferenceTo = 'AdministrativeUnit.Groups'               # reference to the Administrative Unit defined below to add the role
                        Justification                 = 'Manage group-based licensing for dedicated, cloud-native Cloud Administrator accounts'
                    }
                    @{
                        DisplayName    = 'User Administrator'
                        RoleTemplateId = 'fe930be7-5e62-47db-91af-98c3a49a38b1'                 # RoleTemplateId is optional, but recommended to ensure the correct role is assigned.
                        Justification  = 'Create new dedicated, cloud-native Cloud Administrator accounts before they are automatically added to the Management Restricted Administrative Units'
                    }
                    @{
                        DisplayName                   = 'User Administrator'
                        RoleTemplateId                = 'fe930be7-5e62-47db-91af-98c3a49a38b1'    # RoleTemplateId is optional, but recommended to ensure the correct role is assigned.
                        AdministrativeUnitReferenceTo = 'AdministrativeUnit.AdminUsersT0'         # reference to the Administrative Unit defined below to add the role
                        Justification                 = 'Manage dedicated, cloud-native Cloud Administrator accounts in Tier 0'
                    }
                    @{
                        DisplayName                   = 'User Administrator'
                        RoleTemplateId                = 'fe930be7-5e62-47db-91af-98c3a49a38b1'    # RoleTemplateId is optional, but recommended to ensure the correct role is assigned.
                        AdministrativeUnitReferenceTo = 'AdministrativeUnit.AdminUsersT1'         # reference to the Administrative Unit defined below to add the role
                        Justification                 = 'Manage dedicated, cloud-native Cloud Administrator accounts in Tier 1'
                    }
                    @{
                        DisplayName                   = 'User Administrator'
                        RoleTemplateId                = 'fe930be7-5e62-47db-91af-98c3a49a38b1'    # RoleTemplateId is optional, but recommended to ensure the correct role is assigned.
                        AdministrativeUnitReferenceTo = 'AdministrativeUnit.AdminUsersT2'         # reference to the Administrative Unit defined below to add the role
                        Justification                 = 'Manage dedicated, cloud-native Cloud Administrator accounts in Tier 2'
                    }
                    @{
                        DisplayName                   = 'Privileged Authentication Administrator'
                        RoleTemplateId                = '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'    # RoleTemplateId is optional, but recommended to ensure the correct role is assigned.
                        AdministrativeUnitReferenceTo = 'AdministrativeUnit.AdminUsersT0'         # reference to the Administrative Unit defined below to add the role
                        Justification                 = 'Manage authentication methods for dedicated, cloud-native Cloud Administrator accounts in Tier 0'
                    }
                    @{
                        DisplayName                   = 'Privileged Authentication Administrator'
                        RoleTemplateId                = '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'    # RoleTemplateId is optional, but recommended to ensure the correct role is assigned.
                        AdministrativeUnitReferenceTo = 'AdministrativeUnit.AdminUsersT1'         # reference to the Administrative Unit defined below to add the role
                        Justification                 = 'Manage authentication methods for dedicated, cloud-native Cloud Administrator accounts in Tier 1'
                    }
                    @{
                        DisplayName                   = 'Privileged Authentication Administrator'
                        RoleTemplateId                = '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'    # RoleTemplateId is optional, but recommended to ensure the correct role is assigned.
                        AdministrativeUnitReferenceTo = 'AdministrativeUnit.AdminUsersT2'         # reference to the Administrative Unit defined below to add the role
                        Justification                 = 'Manage authentication methods for dedicated, cloud-native Cloud Administrator accounts in Tier 2'
                    }
                )

                # App registrations and their permissions for the Managed Identity.
                AppPermissions = @(

                    @{
                        DisplayName = 'Microsoft Graph'
                        AppId       = '00000003-0000-0000-c000-000000000000'   # AppId is optional, but recommended to ensure the roles are assigned to the correct app.

                        # Note: Required AppRoles depend on your runbooks and modules.
                        AppRoles    = @(
                            'AuditLog.Read.All'
                            'Directory.Read.All'
                            'Directory.Write.Restricted'
                            'Group.Read.All'
                            'Group.ReadWrite.All'
                            'Mail.Send'
                            'OnPremDirectorySynchronization.Read.All'
                            'Organization.Read.All'
                            'Policy.Read.All'
                            'User.Read.All'
                            'User.ReadWrite.All'
                            'UserAuthenticationMethod.ReadWrite.All'
                        )

                        # # Note: Required Oauth2PermissionScopes depend on your runbooks and modules.
                        # Oauth2PermissionScopes = @{
                        #     Admin = @(
                        #         'offline_access'
                        #         'openid'
                        #         'profile'
                        #     )
                        #     '<User-ObjectId>' = @(
                        #     )
                        # }
                    }

                    @{
                        DisplayName = 'Office 365 Exchange Online'
                        AppId       = '00000002-0000-0ff1-ce00-000000000000'   # AppId is optional, but recommended to ensure the roles are assigned to the correct app.

                        # Note: Required AppRoles depend on your runbooks and modules.
                        AppRoles    = @(
                            'Exchange.ManageAsApp'  # Allow using EXO PowerShell V3 module
                        )

                        # # Note: Required Oauth2PermissionScopes depend on your runbooks and modules.
                        # Oauth2PermissionScopes = @{
                        #     Admin = @(
                        #     )
                        #     '<User-ObjectId>' = @(
                        #     )
                        # }
                    }
                )
            }
        )

        # Administrative Units you want to create in your Entra ID tenant.
        AdministrativeUnit           = @{
            #region Administrative Unit for Break Glass access
            'BreakGlass'   = @{
                DisplayName                  = 'CORP-T0-S-Break-Glass-RestrictedAdminUnit'
                Id                           = '' # After creation, you can set the ID here for future reference to be independent of DisplayName changes.
                Description                  = 'Tier0 objects for Break Glass access. DO NOT CHANGE!'
                IsMemberManagementRestricted = $true
                Visibility                   = 'HiddenMembership'

                # HINT: Make sure to manually add your break glass accounts to this Administrative Unit. This is not done automatically.
                #       See https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access for more information about how to create and use break glass accounts.
            }
            #endregion

            #region Administrative Units for groups belonging to Cloud Administration
            'Groups'       = @{
                DisplayName                  = 'CORP-T0-S-Cloud-Administration-Groups-RestrictedAdminUnit'
                Id                           = '' # After creation, you can set the ID here for future reference to be independent of DisplayName changes.
                Description                  = 'Groups for Privileged Cloud Administration in Tier 0, 1, and 2'
                IsMemberManagementRestricted = $true
                Visibility                   = 'HiddenMembership'

                # Scopable directory roles that shall be assigned to the current user during initial creation.
                # This is essential if the admin unit is management-restricted and groups are created in it.
                # This is required also for users with 'Global Administrator' or 'Privileged Role Administrator' role assignments.
                #
                # Note that after the initial creation, you can manually assign additional roles to the user or delegate the role assignment
                # to other users (requires either the 'Privileged Role Administrator' or 'Global Administrator' role).
                InitialRoleAssignment        = @(
                    @{
                        DisplayName    = 'Groups Administrator'
                        RoleTemplateId = 'fdd7a751-b60b-444a-984c-02652fe8fa1c'     # RoleTemplateId is optional, but recommended to ensure the correct role is assigned.
                        AssignmentType = 'Eligible'                                 # 'Eligible' or 'Active'
                        Duration       = 'P3M'                                      # Duration is optional, but recommended to ensure the role assignment is temporary.
                        Justification  = 'Temporarily manage groups for Privileged Cloud Administration in Tier 0, 1, and 2'
                    }
                    @{
                        DisplayName    = 'License Administrator'
                        RoleTemplateId = '4d6ac14f-3453-41d0-bef9-a3e0c569773a'
                        AssignmentType = 'Eligible'
                        Duration       = 'P3M'
                        Justification  = 'Manage group-based licensing for dedicated, cloud-native Cloud Administrator accounts'
                    }
                )
            }
            #endregion

            #region Dynamic Administrative Units for dedicated, cloud-native Cloud Administrator accounts
            'AdminUsersT0' = @{
                DisplayName                   = 'CORP-T0-D-Tier0-Admin-Users-RestrictedAdminUnit'
                Id                            = '' # After creation, you can set the ID here for future reference to be independent of DisplayName changes.
                Description                   = 'Privileged Users for Cloud Administration in Tier 0'
                IsMemberManagementRestricted  = $true
                Visibility                    = 'HiddenMembership'
                MembershipType                = 'Dynamic'
                MembershipRule                = @'
                    (user.userType -eq "Member") and
                    (user.onPremisesSecurityIdentifier -eq null) and
                    (user.userPrincipalName -notMatch "^.+#EXT#@.+\.onmicrosoft\.com$") and
                    (
                        (user.userPrincipalName -match "A0C-.+@.+$") or
                        (user.extensionAttribute15 -startsWith "A0C")
                    )
'@
                MembershipRuleProcessingState = 'On'

                # Scopable directory roles that shall be assigned to the current user during initial creation.
                # This is essential if the admin unit is management-restricted and groups are created in it.
                # This is required also for users with 'Global Administrator' or 'Privileged Role Administrator' role assignments.
                #
                # Note that after the initial creation, you can manually assign additional roles to the user or delegate the role assignment
                # to other users (requires either the 'Privileged Role Administrator' or 'Global Administrator' role).
                InitialRoleAssignment         = @(
                    @{
                        DisplayName    = 'User Administrator'
                        RoleTemplateId = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
                        AssignmentType = 'Eligible'
                        Duration       = 'P3M'
                        Justification  = 'Temporarily manage dedicated, cloud-native Cloud Administrator accounts in Tier 0'
                    }
                    @{
                        DisplayName    = 'Privileged Authentication Administrator'
                        RoleTemplateId = '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'
                        AssignmentType = 'Eligible'
                        Duration       = 'P3M'
                        Justification  = 'Temporarily manage dedicated, cloud-native Cloud Administrator accounts in Tier 0'
                    }
                )
            }

            'AdminUsersT1' = @{
                DisplayName                   = 'CORP-T0-D-Tier1-Admin-Users-RestrictedAdminUnit'
                Id                            = '' # After creation, you can set the ID here for future reference to be independent of DisplayName changes.
                Description                   = 'Privileged Users for Cloud Administration in Tier 1'
                IsMemberManagementRestricted  = $true
                Visibility                    = 'HiddenMembership'
                MembershipType                = 'Dynamic'
                MembershipRule                = @'
                    (user.userType -eq "Member") and
                    (user.onPremisesSecurityIdentifier -eq null) and
                    (user.userPrincipalName -notMatch "^.+#EXT#@.+\.onmicrosoft\.com$") and
                    (
                        (user.userPrincipalName -match "A1C-.+@.+$") or
                        (user.extensionAttribute15 -startsWith "A1C")
                    )
'@
                MembershipRuleProcessingState = 'On'

                # Scopable directory roles that shall be assigned to the current user during initial creation.
                # This is essential if the admin unit is management-restricted and groups are created in it.
                # This is required also for users with 'Global Administrator' or 'Privileged Role Administrator' role assignments.
                #
                # Note that after the initial creation, you can manually assign additional roles to the user or delegate the role assignment
                # to other users (requires either the 'Privileged Role Administrator' or 'Global Administrator' role).
                InitialRoleAssignment         = @(
                    @{
                        DisplayName    = 'User Administrator'
                        RoleTemplateId = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
                        AssignmentType = 'Eligible'
                        Duration       = 'P3M'
                        Justification  = 'Temporarily manage dedicated, cloud-native Cloud Administrator accounts in Tier 1'
                    }
                    @{
                        DisplayName    = 'Privileged Authentication Administrator'
                        RoleTemplateId = '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'
                        AssignmentType = 'Eligible'
                        Duration       = 'P3M'
                        Justification  = 'Temporarily manage dedicated, cloud-native Cloud Administrator accounts in Tier 1'
                    }
                )
            }

            'AdminUsersT2' = @{
                DisplayName                   = 'CORP-T0-D-Tier2-Admin-Users-RestrictedAdminUnit'
                Id                            = '' # After creation, you can set the ID here for future reference to be independent of DisplayName changes.
                Description                   = 'Privileged Users for Cloud Administration in Tier 2'
                IsMemberManagementRestricted  = $true
                Visibility                    = 'HiddenMembership'
                MembershipType                = 'Dynamic'
                MembershipRule                = @'
                    (user.userType -eq "Member") and
                    (user.onPremisesSecurityIdentifier -eq null) and
                    (user.userPrincipalName -notMatch "^.+#EXT#@.+\.onmicrosoft\.com$") and
                    (
                        (user.userPrincipalName -match "A2C-.+@.+$") or
                        (user.extensionAttribute15 -startsWith "A2C")
                    )
'@
                MembershipRuleProcessingState = 'On'

                # Scopable directory roles that shall be assigned to the current user during initial creation.
                # This is essential if the admin unit is management-restricted and groups are created in it.
                # This is required also for users with 'Global Administrator' or 'Privileged Role Administrator' role assignments.
                #
                # Note that after the initial creation, you can manually assign additional roles to the user or delegate the role assignment
                # to other users (requires either the 'Privileged Role Administrator' or 'Global Administrator' role).
                InitialRoleAssignment         = @(
                    @{
                        DisplayName    = 'User Administrator'
                        RoleTemplateId = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
                        AssignmentType = 'Eligible'
                        Duration       = 'P3M'
                        Justification  = 'Temporarily manage dedicated, cloud-native Cloud Administrator accounts in Tier 2'
                    }
                    @{
                        DisplayName    = 'Privileged Authentication Administrator'
                        RoleTemplateId = '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'
                        AssignmentType = 'Eligible'
                        Duration       = 'P3M'
                        Justification  = 'Temporarily manage dedicated, cloud-native Cloud Administrator accounts in Tier 2'
                    }
                )
            }
            #endregion
        }

        # Groups you want to create in your Entra ID tenant.
        Group                        = @{
            #region Group for Break Glass access
            'BreakGlass'          = @{
                AdministrativeUnitReferenceTo = 'AdministrativeUnit.BreakGlass'   # reference to the Administrative Unit defined above to add the group
                DisplayName                   = 'CORP-T0-S-Break-Glass-Admins'
                Id                            = '' # After creation, you can set the ID here for future reference to be independent of DisplayName changes.
                Description                   = 'Global group for emergency break glass accounts'
                Visibility                    = 'Private'
                SecurityEnabled               = $true
                MailEnabled                   = $false

                # HINT: Make sure to manually add your break glass accounts to this Administrative Unit. This is not done automatically.
                #       See https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access for more information about how to create and use break glass accounts.
            }
            #endregion

            #region Groups for Cloud Administrators in Tier 0, 1, and 2
            'AdminUsersT0'        = @{
                AdministrativeUnitReferenceTo = 'AdministrativeUnit.Groups'   # reference to the Administrative Unit defined above to add the group
                DisplayName                   = 'CORP-T0-S-Privileged-Role-Tier0-Users'
                Id                            = '' # After creation, you can set the ID here for future reference to be independent of DisplayName changes.
                Description                   = 'Tier 0 Cloud Administrators'
                Visibility                    = 'Private'
                SecurityEnabled               = $true
                MailEnabled                   = $false
            }

            'AdminUsersT1'        = @{
                AdministrativeUnitReferenceTo = 'AdministrativeUnit.Groups'   # reference to the Administrative Unit defined above to add the group
                DisplayName                   = 'CORP-T0-S-Privileged-Role-Tier1-Users'
                Id                            = '' # After creation, you can set the ID here for future reference to be independent of DisplayName changes.
                Description                   = 'Tier 1 Cloud Administrators'
                Visibility                    = 'Private'
                SecurityEnabled               = $true
                MailEnabled                   = $false
            }

            'AdminUsersT2'        = @{
                AdministrativeUnitReferenceTo = 'AdministrativeUnit.Groups'   # reference to the Administrative Unit defined above to add the group
                DisplayName                   = 'CORP-T0-S-Privileged-Role-Tier2-Users'
                Id                            = '' # After creation, you can set the ID here for future reference to be independent of DisplayName changes.
                Description                   = 'Tier 2 Cloud Administrators'
                Visibility                    = 'Private'
                SecurityEnabled               = $true
                MailEnabled                   = $false
            }
            #endregion

            #region Group-based licensing for dedicated, cloud-native Cloud Administrator accounts
            'AdminUsersT0License' = @{
                AdministrativeUnitReferenceTo = 'AdministrativeUnit.Groups'   # reference to the Administrative Unit defined above to add the group
                DisplayName                   = 'CORP-T0-D-Tier0-Admin-Users-Licensing'
                Id                            = '' # After creation, you can set the ID here for future reference to be independent of DisplayName changes.
                Description                   = 'Licensing for dedicated, cloud-native Tier 0 Cloud Administrator accounts'
                Visibility                    = 'Private'
                SecurityEnabled               = $true
                MailEnabled                   = $false
                GroupTypes                    = @(
                    'DynamicMembership'
                )
                MembershipRule                = @'
                    (user.accountEnabled -eq true) and
                    (user.userType -eq "Member") and
                    (user.onPremisesSecurityIdentifier -eq null) and
                    (user.userPrincipalName -notMatch "^.+#EXT#@.+\.onmicrosoft\.com$") and
                    (user.extensionAttribute15 -startsWith "A0C")
'@
                MembershipRuleProcessingState = 'On'

                # Licenses that shall be assigned to the group during initial creation.
                # Note that after the initial creation, you can manually change licenses of the group.
                # (requires the 'Groups Administrator' and 'License Administrator' roles).
                InitialLicenseAssignment      = @(
                    @{
                        SkuPartNumber = 'EXCHANGEDESKLESS'
                        # SkuId = '00000000-0000-0000-0000-000000000000'    # Replace with the SKU ID of the license you want to assign. Otherwise, it will be determined automatically from the SkuPartNumber.
                        EnabledPlans  = @( # If you want to enable only specific service plans, add their full or partial name here. Otherwise, all service plans of the license will be enabled.
                            'EXCHANGE'
                        )
                        DisabledPlans = @( # If you want to disable specific service plans, add their full or partial name here. Otherwise, all service plans of the license will be enabled.
                        )
                    }
                )
            }

            'AdminUsersT1License' = @{
                AdministrativeUnitReferenceTo = 'AdministrativeUnit.Groups'   # reference to the Administrative Unit defined above to add the group
                DisplayName                   = 'CORP-T0-D-Tier1-Admin-Users-Licensing'
                Id                            = '' # After creation, you can set the ID here for future reference to be independent of DisplayName changes.
                Description                   = 'Licensing for dedicated, cloud-native Tier 1 Cloud Administrator accounts'
                Visibility                    = 'Private'
                SecurityEnabled               = $true
                MailEnabled                   = $false
                GroupTypes                    = @(
                    'DynamicMembership'
                )
                MembershipRule                = @'
                    (user.accountEnabled -eq true) and
                    (user.userType -eq "Member") and
                    (user.onPremisesSecurityIdentifier -eq null) and
                    (user.userPrincipalName -notMatch "^.+#EXT#@.+\.onmicrosoft\.com$") and
                    (user.extensionAttribute15 -startsWith "A1C")
'@
                MembershipRuleProcessingState = 'On'

                # Licenses that shall be assigned to the group during initial creation.
                # Note that after the initial creation, you can manually change licenses of the group.
                # (requires the 'Groups Administrator' and 'License Administrator' roles).
                InitialLicenseAssignment      = @(
                    @{
                        SkuPartNumber = 'EXCHANGEDESKLESS'
                        # SkuId = '00000000-0000-0000-0000-000000000000'    # Replace with the SKU ID of the license you want to assign. Otherwise, it will be determined automatically from the SkuPartNumber.
                        EnabledPlans  = @( # If you want to enable only specific service plans, add their full or partial name here. Otherwise, all service plans of the license will be enabled.
                            'EXCHANGE'
                        )
                        DisabledPlans = @( # If you want to disable specific service plans, add their full or partial name here. Otherwise, all service plans of the license will be enabled.
                        )
                    }
                )
            }

            'AdminUsersT2License' = @{
                AdministrativeUnitReferenceTo = 'AdministrativeUnit.Groups'   # reference to the Administrative Unit defined above to add the group
                DisplayName                   = 'CORP-T0-D-Tier2-Admin-Users-Licensing'
                Id                            = '' # After creation, you can set the ID here for future reference to be independent of DisplayName changes.
                Description                   = 'Licensing for dedicated, cloud-native Tier 2 Cloud Administrator accounts'
                Visibility                    = 'Private'
                SecurityEnabled               = $true
                MailEnabled                   = $false
                GroupTypes                    = @(
                    'DynamicMembership'
                )
                MembershipRule                = @'
                    (user.accountEnabled -eq true) and
                    (user.userType -eq "Member") and
                    (user.onPremisesSecurityIdentifier -eq null) and
                    (user.userPrincipalName -notMatch "^.+#EXT#@.+\.onmicrosoft\.com$") and
                    (user.extensionAttribute15 -startsWith "A2C")
'@
                MembershipRuleProcessingState = 'On'

                # Licenses that shall be assigned to the group during initial creation.
                # Note that after the initial creation, you can manually change licenses of the group.
                # (requires the 'Groups Administrator' and 'License Administrator' roles).
                InitialLicenseAssignment      = @(
                    @{
                        SkuPartNumber = 'EXCHANGEDESKLESS'
                        # SkuId = '00000000-0000-0000-0000-000000000000'    # Replace with the SKU ID of the license you want to assign. Otherwise, it will be determined automatically from the SkuPartNumber.
                        EnabledPlans  = @( # If you want to enable only specific service plans, add their full or partial name here. Otherwise, all service plans of the license will be enabled.
                            'EXCHANGE'
                        )
                        DisabledPlans = @( # If you want to disable specific service plans, add their full or partial name here. Otherwise, all service plans of the license will be enabled.
                        )
                    }
                )
            }
            #endregion
        }
    }
}
