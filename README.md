<!-- Based on README.md template by https://github.com/othneildrew/Best-README-Template -->

<a name="readme-top"></a>

<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
<div align="center">

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
[![Workoho][Workoho]][Workoho-url]

</div>

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/workoho/Entra-Tiering-Security-Model">
    <img src="images/logo.svg" alt="Logo" width="180" height="180">
  </a>

<h3 align="center">Cloud Administration Tiering Security Model for Microsoft Entra</h3>

  <p align="center">
    Implement a powerful Tiering Security Model in Microsoft Entra for your Cloud Administrator identities using Azure Automation.
    <br />
    <a href="https://github.com/workoho/Entra-Tiering-Security-Model/wiki"><strong>Explore the docs »</strong></a>
    <br />

[![Open template in GitHub Codespaces](https://img.shields.io/badge/Open%20in-GitHub%20Codespaces-blue?logo=github)](https://codespaces.new/Workoho/Entra-Tiering-Security-Model)
&nbsp;&nbsp;&nbsp;
[![View template online in Visual Studio Code](https://img.shields.io/badge/View%20Online%20in-Visual%20Studio%20Code-blue?logo=visual-studio-code)](https://vscode.dev/github/Workoho/Entra-Tiering-Security-Model)
<br />
<a href="https://github.com/workoho/Entra-Tiering-Security-Model/issues/new?labels=bug&template=bug-report---.md">Report Bug</a>
·
<a href="https://github.com/workoho/Entra-Tiering-Security-Model/issues/new?labels=enhancement&template=feature-request---.md">Request Feature</a>

  </p>
</div>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
        <li><a href="#minimum-permissions-for-the-administrator-account-during-the-initial-interactive-setup-session">Overview of permissions during setup</a></li>
        <li><a href="#minimum-permissions-after-the-setup-of-the-azure-automation-account">Overview of permissions after setup</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#maintainers">Maintainers</a></li>
  </ol>
</details>

<!-- ABOUT THE PROJECT -->

## About The Project

This project provides you with a template for implementing a basic security model for tier separation in your Microsoft cloud environment.
This significantly helps to separate the security of your on-premises and cloud environment and [protect Microsoft 365 from on-premises attacks](https://learn.microsoft.com/en-us/entra/architecture/protect-m365-from-on-premises-attacks).

The implementation and maintenance effort can be uge and requires deep knowledge in multiple Microsoft technologies and security principles. Using this project as a template, it helps to set up highly protected security groups using [Management Restricted Administrative Units](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management) and by delegation of maintenance and provisioning tasks for dedicated, cloud-native Cloud Administrator accounts to a locked [Azure Automation account](https://learn.microsoft.com/en-us/azure/automation/overview) with [System-Assigned Managed Identity](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview).

These highly protected security groups form the basis for the implementation of Microsoft Entra security measures in Conditional Access, such as [Authentication Contexts](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps#authentication-context) for the use of [Activation Rules in Privileged Identity Management](https://learn.microsoft.com/en-us/graph/identity-governance-pim-rules-overview#activation-rules) and [Protected Actions](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/protected-actions-overview).

The following graphic illustrates the tier separation concept at a high level:

[![How the Tier separation works](images/Entra-Tiering-Security-Model-Cloud%20Account%20Tier%20Separation.png "Cloud Administrator Account Tier Separation")](documents/Entra-Tiering-Security-Model-Cloud%20Account%20Tier%20Separation.pdf)

The lifecycle management of dedicated, cloud-native Cloud Administrator accounts is tied to a primary user account. The properties are automatically copied from this account and can be updated regularly to keep them synchronized.

Preferably, the primary account is a company account or can even be an external guest account (not implemented yet). This ties the lifecycle management of the dedicated Cloud Administrator account to the existing lifecycle of the users.

If your Microsoft Entra tenant was configured for [Hybrid Identities](https://learn.microsoft.com/en-us/entra/identity/hybrid/whatis-hybrid-identity), only synchronized identitied from your on-premises Active Directory are eligible to create a cloud administration account.

> :information_source: In case of using guest accounts, we strongly recommend to implement an appropriate lifecycle management first, for example with [EasyLife 365 Collaboration](https://easylife365.cloud/products/collaboration/).
>
> _Workoho_ is an official EasyLife partner. [Contact us](https://workoho.com/kontakt/) if you need help managing your guest identities.

The following graphic illustrates the lifecycle concept at a high level:

[![How lifecycle management for dedicated Cloud Administrator account works](images/Entra-Tiering-Security-Model-Cloud%20Admin%20Lifecycle.png "Connection between Dedicated Cloud Administrator and Primary Account")](documents/Entra-Tiering-Security-Model-Cloud%20Admin%20Lifecycle.pdf)

### Built With

<div align="center">

[![Azure Automation Framework][AzAutoFW]][AzAutoFW-url]
[![GitHub Codespaces][GitHubCodespaces]][GitHubCodespaces-url]
[![Visual Studio Code][VScode]][VScode-url]
[![PowerShell][PowerShell]][PowerShell-url]

</div>

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- GETTING STARTED -->

## Getting Started

The entire setup is fully automatic (thanks to the amazing [Azure Automation Common Runbook Framework](https://github.com/workoho/AzAuto-Common-Runbook-FW)), but requires some preparation and decision making to start.

[![asciicast](https://asciinema.org/a/646552.svg)](https://asciinema.org/a/646552)
_Preview of the setup procedure_

### Prerequisites

Your Microsoft Entra ID tenant must be enabled and licensed for [Privileged Identity Management](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure), which is a premium feature and part of the Microsoft Entra ID P2 licensing plan. Note that this could also be part of your Microsoft 365 E5 or Enterprise Mobility & Security E5 license. Visit [Sign up for Microsoft Entra ID P1 or P2 editions
](https://learn.microsoft.com/en-us/entra/fundamentals/get-started-premium) on Microsoft Learn for further information.

You must also have free Exchange Online licenses for each dedicated Cloud Administrator account to enable email forwarding. _Exchange Online Kiosk_ is a good and cost-effective solution, but any other license with an Exchange service plan is also suitable.

Furthermore, [emergency access admin accounts](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access) must be in place to have them available for _"break glass"_ scenarios.

We assume that the following requirements for your local Windows, macOS, or Linux machine are already met and do not describe them in detail here:

1. [Git](https://learn.microsoft.com/en-us/devops/develop/git/install-and-set-up-git) is installed.
2. [PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell) is installed.

   We recommend using the latest version of PowerShell Core, but Windows PowerShell should do as well.

3. Optional: [7-Zip](https://www.7-zip.org/download.html) is installed. This may be used to encrypt configuration files if you would like to protect their content, but still check them into your Git repository.

4. Following PowerShell modules are installed:

   - `Az`
   - `Microsoft.Graph`

   For local run and/or development, further modules are required:

   - `ExchangeOnlineManagement`

5. Might be optional, but _highly recommended_: [Visual Studio Code](https://code.visualstudio.com/docs/setup/setup-overview) is installed.

6. On Windows, it is preferred to have [SeCreateSymbolicLinkPrivilege](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/create-symbolic-links) enabled for your local user account. However, this is not a fixed requirement.

> :heart_decoration: Or: You forget about all of these dependencies and start right away with our prepared build and runtime environment using GitHub Codespaces: No time to setup your local machine, no policy restrictions - simply start effortless :sunglasses:
>
> [![Open template in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/Workoho/Entra-Tiering-Security-Model)
>
> Alternatively, you may use any type of [development container](https://code.visualstudio.com/docs/devcontainers/containers) with your local Visual Studio Code setup. We provide pre-configured Docker containers for Windows Subsystem for Linux (Intel x64), Linux (Intel x64 and ARM64), and macOS (Intel x64 and Apple Silicon).
>
> For further information, read [Choosing your development environment](https://code.visualstudio.com/docs/containers/choosing-dev-environment) at Visual Studio Code Docs.

### Installation

The following steps only need to be performed once to get you started:

1. Open a PowerShell command line prompt.
2. Make a local clone of this repository and change to the directory afterwards:

   ```powershell
   $CORP='CORP'
   mkdir $CORP
   cd $CORP
   git clone https://github.com/workoho/Entra-Tiering-Security-Model.git $CORP.Entra-Tiering-Security-Model
   cd $CORP.Entra-Tiering-Security-Model

   # Rename the Visual Studio Code workspace
   Rename-Item ./Entra-Tiering-Security-Model.code-workspace $CORP.Entra-Tiering-Security-Model.code-workspace

   # Remove the remote tracking and rename the remote from 'origin' to 'base' for future updating
   git branch --unset-upstream main
   git remote rename origin base
   ```

   You should set `$CORP` to your company name code to indicate that this is containing your own setup.

   Note that we are also creating a dedicated folder for our project. In step 3, we are going to clone a second repository containing the Azure Automation Common Runbook Framework code that lives in parallel to our project repository. In case you are dealing with different environments, this ensures each environment uses its own copy of the framework and can check out their version of the framework without interfering your other environment.

   - _Optional:_ You may add your own remote respository to upload your local changes, for example to an empty (private) repository you have created in your own GitHub organization:

     ```powershell
     git remote add origin git@github.com:username/CORP.Entra-Tiering-Security-Model.git
     git push --set-upstream origin main
     git push --tags origin
     ```

     Note that the URL depends on how you authenticate and access your remote repository and may look different.
     For example, if you prefer to access your repository via HTTPS instead of SSH, the command would look like this:

     ```powershell
     git remote add origin https://github.com/username/CORP.Entra-Tiering-Security-Model.git
     git push --set-upstream origin main
     git push --tags origin
     ```

3. Trigger downloading the upstream Azure Automation Common Runbook Framework:

   ```powershell
   ./scripts/AzAutoFWProject/Update-AzAutoFWProject.ps1
   ```

   This will automatically clone the upstream framework into a directory that is parallel to your project repository.
   It will automatically check out the desired version of the framework, based on your settings in `./config/AzAutoFWProject/AzAutoFWProject.psd1`. The default is a static reference to the latest stable version at the time you cloned the repository.

   The resulting folder structure now should look like this:

   ```plaintext
   PS> dir ..

       Directory: /Users/me/Developer/CORP

   UnixMode    User  Group  LastWriteTime     Size  Name
   ----------  ----  -----  ----------------  ----  ----
   drwxr-xr-x  me    staff  06.03.2024 10:20  640   AzAuto-Common-Runbook-FW
   drwxr-xr-x  me    staff  06.03.2024 10:20  672   CORP.Entra-Tiering-Security-Model
   ```

   Also, shared resources like script and runbooks will either be copied into your project repository, or symlinked (depending on your operating system and its settings). For example, on **macOS** and **Linux** (including Windows Subsystem for Linux), symlinking shared resources is the default behaviour to ensure they will always be in sync.

   On **Windows**, symlinking may only be used if the [SeCreateSymbolicLinkPrivilege](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/create-symbolic-links) permission was enabled for your local user account. Otherwise, the resources will be copied. If you would like to update the shared resources, you may execute the `./scripts/AzAutoFWProject/Update-AzAutoFWProject.ps1` update script at any time.

   **Good to know:** When you open the project repository in _Visual Studio Code_, an [automated task](https://code.visualstudio.com/docs/editor/tasks) will run the update script so you don't have to.

4. The configuration is splitted into two separate files:

   1. Local configuration in `./config/AzAutoFWProject/AzAutoFWProject.local.psd1`:

      This file typically exists on your local machine only. It may contain parts of the configuration that you consider to be confidential for your company.

      The `Update-AzAutoFWProject.ps1` script you ran before already should have created a copy for you but you may also do this manually:

      Copy the configuration template from `./config/AzAutoFwProject/AzAutoFWProject.local.template.psd1` to `./config/AzAutoFwProject/AzAutoFWProject.local.psd1`:

      ```powershell
      copy ./config/AzAutoFWProject/AzAutoFWProject.local.template.psd1 ./config/AzAutoFWProject/AzAutoFWProject.local.psd1
      ```

      Please note that by default, this configuration file is ignored by the Git repository to avoid accidential leaks of potential sensitive information.

   2. Public configuration in `./config/AzAutoFWProject/AzAutoFWProject.psd1`:

      This file is part of your Git project repository and subject to tracking of changes. Essential parts of the configuration are done in this file where the general information is not considered a secret and its content is to be shared with everyone with access to your Git repository.

      The `Update-AzAutoFWProject.ps1` script you ran before already should have created a copy for you but you may also do this manually:

      Copy the configuration template from `./config/AzAutoFwProject/AzAutoFWProject.template.psd1` to `./config/AzAutoFwProject/AzAutoFWProject.psd1`:

      ```powershell
      copy ./config/AzAutoFWProject/AzAutoFWProject.template.psd1 ./config/AzAutoFWProject/AzAutoFWProject.psd1
      ```

   **Important:** Some parts of the configuration may be moved between the two files. However, it is not a general concept and is only supported where it is explicitly explained.

5. Open `./config/AzAutoFWProject/AzAutoFWProject.local.psd1` in your favorite editor.

   This project template provides a pre-configured build and development environment for _Visual Studio Code_, which is why we recommend using this to edit configuration files. You will also be able to collapse and extend longer regions and sections to maneuver through it.

   In this configuration file, you will need to enter details like:

   - `Name`

     Name your Automation Account to whatever you like, e.g. `prodsub-germanywestcentral-aa001`.

     Note that you will not be able to change the account name after the Automation Account was created.

   - `TenantId`

     The UUID of your Microsoft Entra ID tenant, e.g. `e83262cb-7b0b-4d13-9496-455b378896e4`.

   - `SubscriptionId`

     The UUID of your Azure Subscription, e.g. `f47626a6-2970-41a8-b44c-a4a14ccff181`.

     Please note that the subscription **must** be associated to the `TenantId`.

   - `ResourceGroupName`

     The name of the resource group where you want your Azure Automation Account to live.

     Please note that a pre-existing resource group **must** be in the `SubscriptionId` you entered before.
     If this resource group does not exist yet, it will automatically be created in the given subscription. You must have at least `Contributor` role assigned for the subscription for this to work (also see minimum permissions for [1. Azure roles](#1-setup-azure-roles) below).

   As mentioned earliert, this file is by default not tracked in the Git repository. Here are a few options how you can backup this file:

   - _Option 1 (Preferred):_ Store on a local server and keep it separate from the Git repository.

     This is the safest option, but might not be easy to handle during daily operations when you need to find the file later.

   - _Option 2:_ Encrypted ZIP archive using 7-zip.

     As a compromise, you may add the file to an encrypted ZIP archive and add this file to the repository:

     ```powershell
     cd ./config/AzAutoFWProject/
     7z a -p -tzip AzAutoFWProject.local.psd1.zip AzAutoFWProject.local.psd1
     git add --force AzAutoFWProject.local.psd1.zip
     git commit -m "Add ZIP-encrypted file of AzAutoFWProject.local.psd1"
     git push
     cd -
     ```

     Attention: Make sure that you are actually adding the `.zip` file, _not_ the plain `.psd1` file (fans using [tab completion](https://learn.microsoft.com/en-us/powershell/scripting/learn/shell/tab-completion) might know what I mean).

     Of course, you must remember the password. We recommend using a password manager to generate a long random password.
     If you ever want to use this file on a different machine, you will need this password to unpack the file.

   - _Option 3:_ Force adding it to the Git repository.

     If you decide to add it to your repository, it is strongly recommended to ensure only selected persons have read access to the repository to keep this information safe:

     ```powershell
     git add --force ./config/AzAutoFWProject/AzAutoFWProject.local.psd1
     git commit -m "Forcibly add AzAutoFWProject.local.psd1"
     git push
     ```

6. Review and adjust default settings in `./config/AzAutoFWProject/AzAutoFWProject.psd1` to your liking.

   You want to pay special attention to these three sections:

   1. `ManagedIdentity`

      Review the permissions that will permanently assigned to the System-Assigned Managed Identity of the Automation Account. A short justification information is provided in the configuration file so you can understand what the permissions are used for. Removing any of them will result in runbooks not working anymore.

   2. `AdministrativeUnit`

      Review the `DisplayName` for the Administrative Units to be be created and the desired permissions that the administrator account you are using for the setup will receive.

      You may also pay attention at the specific settings that are not quite common, like enabling [Restricted Management](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management), or restricting the membership visibility. Note that these two settings can only be set during creation and not changed afterwards.

      The `MembershipRule` setting for dynamic membership is also something to look at. If you want to change the default naming schema for your dedicated Cloud Administrator accounts, you will need to adjust the rules accordingly.
      Please note that in that case you will also need to add additional Automation Variables for the `CloudAdmin_0100__New-CloudAdministrator-Account.ps1` runbook to know about your desired prefix and suffix preferences.

   3. `Group`

      Review the `DisplayName` for the cloud security groups to be created.

      You should also look at the `InitialLicenseAssignment` to validate the license assignment setup for the group, or remove that part if you prefer to handle this manually after the groups were created. Essentially, an Exchange Online mailbox is mandatory for each dedicated Cloud Administrator account that the `CloudAdmin_0100__New-CloudAdministrator-Account.ps1` runbook will create. The example provides details to assign Exchange Online Kiosk license and only enable Exchange Online service plan of it.

      > :information_source: You may need to add additional licensing for Microsoft Entra ID P2 to follow corporate compliance policies. If the referring primary user account is already licensed for it, and you can ensure that the dedicated Cloud Administrator account is used exclusively by the same natural person, you are generally entitled to use the features on both accounts, unless it is technically necessary to assign a license to both accounts. This assumption is based on the [Microsoft Universal License Terms for Online Services](https://www.microsoft.com/licensing/terms/product/ForOnlineServices/all) (search for _"Customer must acquire and assign the appropriate subscription licenses ..."_ in the _Licensing the Online Services_ section). **We recommend to validate this with your Microsoft sales representative for your special situation.** We do not provide any legal advice at this point.
      >
      > To add licenses to the configuration, you find the required `SkuPartNumber` and `ServicePlanName` details on the Microsoft Learn page about [Product names and service plan identifiers for licensing](https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference). Some products may have multiple SKU Part Numbers (String IDs). To ensure you are using the correct `SkuPartNumber`, you may use [`Get-MgSubscribedSku`](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.directorymanagement/get-mgsubscribedsku) to validate this for your tenant:
      >
      > ```powershell
      > Connect-MgGraph -ContextScope Process -Scopes Organization.Read.All
      > Get-MgSubscribedSku | Where-Object SkuPartNumber -like '*M365_F1*'
      > ```

      The `MembershipRule` setting for dynamic membership is again something to look at here as well. If you want to change the default naming schema for your dedicated cloud-native Cloud Administrator accounts, you will need to adjust the rules accordingly.
      Please note that in that case you will also need to add additional Automation Variables for the `CloudAdmin_0100__New-CloudAdministrator-Account.ps1` to know about your desired prefix and suffix settings.

7. Start the initial setup.

   The setup script will actively validate and confirm if the correct roles are active for the current admin user and will give explicit guidance about any missing permissions for the setup to be successful.

   See [Minimum permissions for the administrator account during the initial interactive setup session](#minimum-permissions-for-the-administrator-account-during-the-initial-interactive-setup-session) if you want to prepare this upfront.

   When you are ready, choose one of the setup options below:

   - _Option 1 (Preferred):_ Run the all-at-once script:

     ```powershell
     ./setup/AzAutoFWProject/Invoke-Setup.ps1
     ```

     Dont't worry, the setup script will ask for approval for each change it will perform with detailled information about what it will do afterwards. If you want, you may also use the `-WhatIf` parameter for a dry-run.

     It is also good to know that you may always start the setup script again, for example if there are still missing permissions for it to continue with the setup.

   - _Option 2:_ Go through the setup step-by-step:

     If you prefer to split the setup in parts, for example because you are working together with different teams, you may do so by only starting the part that you desire. However, it is best to keep the order right, which is shown below:

     ```powershell
     # More general parts
     ./setup/AzAutoFWProject/Set-AzAutomationAccount.ps1            # Create the Automation Account
     ./setup/AzAutoFWProject/Set-AzAutomationRuntimeEnvironment.ps1 # Install PowerShell modules in the runtime environment of the Automation Account
     ./setup/AzAutoFWProject/Set-AzAutomationRunbook.ps1            # Upload all common runbooks to the Automation Account in the correct sorting order

     # Critical parts
     ./setup/AzAutoFWProject/Set-EntraAdministrativeUnit.ps1        # Create Restricted Administrative Units
     ./setup/AzAutoFWProject/Set-EntraGroup.ps1                     # Create groups inside the Restricted Administrative Units that were created before
     ./setup/AzAutoFWProject/Set-AzAutomationManagedIdentity.ps1    # Enable System-Assigned Managed Identity and assign desired permissions to it

     # Set configuration
     ./setup/AzAutoFWProject/Set-AzAutomationVariable.ps1           # Create Automation Variables in the Automation Account
     ```

8. Update configuration in `./config/AzAutoFWProject/AzAutoFWProject.psd1`:

   Now that all parts are created, you need to update some of the configurations and add the unique object IDs. Essentially we need to update the Automation Variables that the CloudAdmin runbooks use for their configuration to know what Microsoft Entra Groups and Administrative Units we are using. There are two options to do so:

   - _Option 1 (Preferred):_ Add object IDs to the `AdministrativeUnit` and `Group` section:

     The setup script output gave you information about the object ID's for the _Administrative Units_ and _Groups_. Look for their section in the configuration file and add the object ID to the empty `Id` property.

   - _Option 2:_ Update `AutomationVariable` configuration directly:

     The defintion of the Automation Variables uses an internal reference to the definitions of Administrative Units and Group so that when you followed _Option 1_ from above, their IDs are automatically used. If for any reason you would like to set the object IDs in the Automation Variables directly, you may look to the `AutomationVariable` section in the configuration file and change the `Value` attribute accordingly. Note that in this case you must also remove the `ValueReferenceTo` property.

   Afterwards, re-run the `./setup/AzAutoFWProject/Set-AzAutomationVariable.ps1` script to update the Automation Variables (use with parameter `-UpdateVariableValue`). You may control if their values were updated successfully in the Azure Portal (find the Automation Account and navigate to _Variables_ under _Shared Resources_ in the left navigation).

9. Check your initial configuration into the Git repository.

   After successfully performing the initial setup, it is a good idea now to officially commit your initial setup details to the Git repository and upload them to the remote server:

   ```powershell
   git commit --all --message "Add configuration details after initial setup"
   git push
   ```

10. Cleanup permissions that are no longer necessary for your own administrator account.

    It is **strongly recommended to review the permissions** you have assigned to your administrator account for the setup, as it may now be time to remove some of them. See [Minimum permissions after the setup of the Azure Automation Account](#minimum-permissions-after-the-setup-of-the-azure-automation-account) to give you some guidance.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Minimum permissions for the administrator account <u>during</u> the initial interactive setup session

The setup script `./setup/AzAutoFWProject/Invoke-Setup.ps1` and its sub-scripts require a couple of different roles to perform the setup steps.
The setup script will actively validate and confirm if the correct roles are active for the current admin user and will give explicit guidance about any missing permissions for the setup to be successful.

For the setup procedure to be as simple as possible, you might want to prepare for the following permissions to be available for your admin user:

<a id="1-setup-azure-roles"></a>**1. Azure roles** (see [Azure built-in roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles)):

While you could run the setup script with Azure _Owner_ permissions to fulfill all needs, we recommend following the [principle of least privilege](https://learn.microsoft.com/en-us/entra/identity-platform/secure-least-privileged-access) and only have the following Azure roles active for your administrator account:

Either at _Subscription_ <u>or</u> _Resource Group_ level:

- `Contributor`

  _Justification:_ Create new resource group (if required), new Azure Automation Account and upload new Automation Runbooks.

- `User Access Administrator` _(<u>optional</u> condition: Constrain to Azure `Reader` role)_

  _Justification:_ Delegate Azure `Reader` role to System-Assigned Managed Identity of the Automation Account.

To learn more about Azure role assignments with conditions, visit [Delegate Azure role assignment management to others with conditions](https://learn.microsoft.com/en-us/azure/role-based-access-control/delegate-role-assignments-portal) on Microsoft Learn.

**Important:** Make sure your Azure roles are activated before starting the setup. See [Activate my Azure resource roles in Privileged Identity Management](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-resource-roles-activate-your-roles) if you need help.

<a id="2-setup-entra-roles"></a>**2. Microsoft Entra directory roles** (see [Microsoft Entra built-in roles](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference)):

While you could run the setup script with _Global Administrator_ permissions to fulfill all needs, we recommend following the [principle of least privilege](https://learn.microsoft.com/en-us/entra/identity-platform/secure-least-privileged-access) and only have the following Entra directory roles active for your administrator account:

- `Cloud Application Administrator`

  _Justification:_ Assign app permissions to the System-Assigned Managed Identity of the Automation Account. Also, allow to perform one-time admin consent for scopes (application roles) of the _Microsoft Graph Command Line Tools_ application (see [3. Microsoft Graph Command Line Tools](#3-setup-microsoft-graph-scopes)).

- `Privileged Role Administrator`

  _Justification:_ Assign Entra directory roles to System-Assigned Managed Identity of the Azure Automation Account. Also, create required Administrative Units in Microsoft Entra.
  This role is also required to supplement the `Cloud Application Administrator` when assigning app permissions to highly-privileged applications like Microsoft Graph.

  For Management Restricted Administrative Units, the setup script will automatically assign [scoped roles](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/custom-overview#scope) as [eligible](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure#terminology) and also activated for 2 hours for the admin running the setup script:

  - `User Administrator` (scoped to the respective Administrative Unit)

    _Justification:_ Allow to manage the dedicated cloud-native Cloud Administrator accounts in the Administrative Unit.

  - `Groups Administrator` (scoped to the respective Administrative Unit)

    _Justification:_ Allow to create and manage the groups belonging to the Cloud Administration Tiering Model.

  - `License Administrator` (scoped to the respective Administrative Unit)

    _Justification:_ Allow to manage group-based licensing for the groups belonging to the Cloud Administration Tiering Model.

  After 2 hours, the activation will automatically expire. The admin user is eligible for the next 3 months to activate the roles again if needed. You may also manually re-configure role assignments for the Restricted Management Administrative Units as you desire. It is **strongly recommended to limit access to Tier 0 Cloud Administrator accounts** only after you completed your migration to the new security model.

**Important:** Make sure your Azure roles are activated before starting the setup. See [Activate a Microsoft Entra role in Privileged Identity Management](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-activate-role) if you need help.

<a id="3-setup-microsoft-graph-scopes"></a>**3. Microsoft Graph Command Line Tools** (see [Microsoft Graph PowerShell](https://learn.microsoft.com/en-us/powershell/microsoftgraph/) and [Microsoft Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference)):

_User consent_:

- `AdministrativeUnit.Read.All`
- `AdministrativeUnit.ReadWrite.All`
- `Application.Read.All`
- `AppRoleAssignment.ReadWrite.All`
- `Directory.Read.All`
- `Directory.Write.Restricted`
- `Group.Read.All`
- `Group.ReadWrite.All`
- `Organization.Read.All`
- `RoleManagement.Read.Directory`
- `RoleManagement.ReadWrite.Directory`

  Due to the `Cloud Application Administrator` directory role mentioned in [2. Microsoft Entra directory roles](#2-setup-entra-roles), the admin user will be able to perform required admin consents right away.

  If you would like to learn more about user and admin consent in Microsoft Entra ID, visit [this page on Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/user-admin-consent-overview).

> :information_source: To pre-approve all required scopes at once, you may run the following command:
>
> ```powershell
> Connect-MgGraph -ContextScope Process -Scopes "AdministrativeUnit.Read.All AdministrativeUnit.ReadWrite.All Application.Read.All AppRoleAssignment.ReadWrite.All Directory.Read.All Directory.Write.Restricted Group.Read.All Group.ReadWrite.All Organization.Read.All RoleManagement.Read.Directory RoleManagement.ReadWrite.Directory"
> ```
>
> Please note that it is highly recommended to refrain from selecting _"Consent on behalf of your organization"_, also known as [admin consent](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/user-admin-consent-overview#admin-consent). Instead, you should work with user consent for each individual user to contribute to the [principle of least privilege](https://learn.microsoft.com/en-us/entra/identity-platform/secure-least-privileged-access).
>
> Note that the appearance of this option depends on your current directory role, for example _Cloud Application Administrator_. If you are presented with an error message, you might need to activate that role first, or [configure the admin consent workflow](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-admin-consent-workflow) so that the consent request can be send to the admin team for approval.
>
> **If you receive an error message or warning in your terminal after you have successfully consented in the browser, it is best to <u>execute the command again</u> to check whether consent has been successfully granted. This is usually successful on the second or third attempt.**

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Minimum permissions <u>after</u> the setup of the Azure Automation Account

After the setup was completed, it is **strongly recommended to reduce the permissions** of the admin user to a minimum.
Also note that this level of access shall be exclusive to Tier 0 Cloud Administrators only as soon as you have finished your migration to the new security model. This is to protect the Automation Account and the System-Assigned Managed Identity as good as possible, due to its high privileges to manage the Cloud Administrator accounts for you.

<a id="1-azure-roles"></a>**1. Azure roles** (see [Azure built-in roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles)):

Either at _Resource Group_ <u>or</u> _Automation Account_ level:

- `Contributor`

  _Justification:_ Maintenance of Azure Automation Account and Automation Runbooks.

  Note that for the _Automation Account_ level, you may also use the `Automation Contributor` role instead.

  <u>**Important:**</u> It is considered a high risk to grant privileges at the subscription or even management group level to a wider public.
  If you decide to grant privileges at these levels, we strongly recommend limiting this access to very few people.

<a id="2-entra-roles"></a>**2. Microsoft Entra directory roles** (see [Microsoft Entra built-in roles](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference)):

For the Management Restricted Administrative Units used for Cloud Administration, [scoped roles](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/custom-overview#scope) can be assigned as [eligible](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure#terminology) for selected Tier 0 administrators that will provide support to other Cloud Administrators:

- `User Administrator` (scoped to the respective Administrative Unit for Tier 0, 1, or 2)

  _Justification:_ Allow to manage the dedicated cloud-native Cloud Administrator accounts of the respective Tier.

- `Groups Administrator` (scoped to the respective Administrative Unit)

  _Justification:_ Allow to manage the groups belonging to the Cloud Administration Tiering Model.

  <u>**Important:**</u> It is considered a high risk to grant access to these groups. Getting access to these groups will allow to manage Cloud Administrator access outside of the Automation Account and without the restrictions and checks the `CloudAdmin_0100__New-CloudAdministrator-Account.ps1` runbook enforces for you. Be aware that this might lead to a security breach if handled in the wrong way!

<a id="3-setup-microsoft-graph-scopes"></a>**3. Microsoft Graph Command Line Tools**:

The _delegated_ permissions you might have added for the _Microsoft Graph Command Line Tools_ during the setup session may be kept.

The nature of delegated permissions is that they also require the respective privileges in Microsoft Entra to be effective.
Visit [Understanding delegated access](https://learn.microsoft.com/en-us/entra/identity-platform/delegated-access-primer) on Microsoft Learn for further details.

Note that revoking _user consent_ permissions currently is only possible using Microsoft Graph, which we don't explicitly describe here.

A good alternative is to restrict access to the _Microsoft Graph Command Line Tools_ enterprise application to selected accounts only. These can even be just your managed cloud administrator accounts if you wish. See [Requiring user assignment for an app](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/what-is-access-management#requiring-user-assignment-for-an-app) and [Manage users and groups assignment to an application](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/assign-user-or-group-access-portal) to learn more.

<!-- USAGE EXAMPLES -->

## Usage

This section requires further attention. :-)

In general, you may have a look to the inline documentation of the runbooks if you would like to start with an idea.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTRIBUTING -->

## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- LICENSE -->

## License

Distributed under the MIT License. See `LICENSE.txt` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- MAINTAINERS -->

## Maintainers

- Julian Pawlowski - [@jpawlowski](https://github.com/jpawlowski)

Project Link: [https://github.com/workoho/Entra-Tiering-Security-Model](https://github.com/workoho/Entra-Tiering-Security-Model)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->

[contributors-shield]: https://img.shields.io/github/contributors/Workoho/Entra-Tiering-Security-Model.svg?style=for-the-badge
[contributors-url]: https://github.com/workoho/Entra-Tiering-Security-Model/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/Workoho/Entra-Tiering-Security-Model.svg?style=for-the-badge
[forks-url]: https://github.com/workoho/Entra-Tiering-Security-Model/network/members
[stars-shield]: https://img.shields.io/github/stars/Workoho/Entra-Tiering-Security-Model.svg?style=for-the-badge
[stars-url]: https://github.com/workoho/Entra-Tiering-Security-Model/stargazers
[issues-shield]: https://img.shields.io/github/issues/Workoho/Entra-Tiering-Security-Model.svg?style=for-the-badge
[issues-url]: https://github.com/workoho/Entra-Tiering-Security-Model/issues
[license-shield]: https://img.shields.io/github/license/Workoho/Entra-Tiering-Security-Model.svg?style=for-the-badge
[license-url]: https://github.com/workoho/Entra-Tiering-Security-Model/blob/master/LICENSE.txt
[AzAutoFW]: https://img.shields.io/badge/Azure_Automation_Framework-1F4386?style=for-the-badge&logo=microsoftazure&logoColor=white
[AzAutoFW-url]: https://github.com/workoho/AzAuto-Common-Runbook-FW
[GitHubCodespaces]: https://img.shields.io/badge/GitHub_Codespaces-09091E?style=for-the-badge&logo=github&logoColor=white
[GitHubCodespaces-url]: https://github.com/features/codespaces
[VScode]: https://img.shields.io/badge/Visual_Studio_Code-2C2C32?style=for-the-badge&logo=visualstudiocode&logoColor=3063B4
[VScode-url]: https://code.visualstudio.com/
[PowerShell]: https://img.shields.io/badge/PowerShell-2C3C57?style=for-the-badge&logo=powershell&logoColor=white
[PowerShell-url]: https://microsoft.com/PowerShell
[Workoho]: https://img.shields.io/badge/Workoho.com-00B3CE?style=for-the-badge&logo=data:image/svg%2bxml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+CjwhRE9DVFlQRSBzdmcgUFVCTElDICItLy9XM0MvL0RURCBTVkcgMS4xLy9FTiIgImh0dHA6Ly93d3cudzMub3JnL0dyYXBoaWNzL1NWRy8xLjEvRFREL3N2ZzExLmR0ZCI+Cjxzdmcgd2lkdGg9IjEwMCUiIGhlaWdodD0iMTAwJSIgdmlld0JveD0iMCAwIDEzNDggOTEzIiB2ZXJzaW9uPSIxLjEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiIHhtbDpzcGFjZT0icHJlc2VydmUiIHhtbG5zOnNlcmlmPSJodHRwOi8vd3d3LnNlcmlmLmNvbS8iIHN0eWxlPSJmaWxsLXJ1bGU6ZXZlbm9kZDtjbGlwLXJ1bGU6ZXZlbm9kZDtzdHJva2UtbGluZWpvaW46cm91bmQ7c3Ryb2tlLW1pdGVybGltaXQ6MjsiPgogICAgPGcgdHJhbnNmb3JtPSJtYXRyaXgoNC4wNzQ3OCwwLDAsMy45NjAzOCwtNzQzMS4xNSwtNDYzNC44OCkiPgogICAgICAgIDxnPgogICAgICAgICAgICA8ZyB0cmFuc2Zvcm09Im1hdHJpeCg4LjY2MzI2ZS0xOCwwLjE0MTQ4MiwtMC4xNDE0ODIsOC42NjMyNmUtMTgsNDA1Ny43MiwtNDI5LjM1KSI+CiAgICAgICAgICAgICAgICA8cGF0aCBkPSJNMTI3MjYsMTM0NTIuN0wxMjc2Mi4zLDEzNDUyLjdMMTI5MzUuOCwxNDE2Ni40TDEyODk2LjEsMTQxNjYuNEwxMjcyNi44LDEzOTQ2LjRMMTI1NDMsMTM4OTAuM0wxMjcyNiwxMzQ1Mi43WiIvPgogICAgICAgICAgICA8L2c+CiAgICAgICAgICAgIDxnIHRyYW5zZm9ybT0ibWF0cml4KDAuMDg0NDk1NCwwLDAsMC4wODQ0OTU0LDE5NDEuOCwxMTA4LjU1KSI+CiAgICAgICAgICAgICAgICA8cGF0aCBkPSJNMTUxOC42MSwyOTk1LjQzTDExOTEuNDksMjk5NS40M0wxMDIyLjcsMzExMS40NkwxMDIyLjcsMzIxNS4wMUwxMjk3LjcsMzIxNS4wMUwxNTE4LjYxLDMwNjIuMDVMMTUxOC42MSwyOTk1LjQzWiIvPgogICAgICAgICAgICA8L2c+CiAgICAgICAgICAgIDxnIHRyYW5zZm9ybT0ibWF0cml4KDAuMDg0NDk1NCwwLDAsMC4wODQ0OTU0LDE4MTQuMDMsMTEwOC41NSkiPgogICAgICAgICAgICAgICAgPHBhdGggZD0iTTE5MTMuNDIsMjk5NS40M0wxMTkxLjQ5LDI5OTUuNDNMMTAyMi43LDMxMTEuNDZMMTAyMi43LDMyMTUuMDFMMTY5Mi41MiwzMjE1LjAxTDE5MTMuNDIsMzA2Mi4wNUwxOTEzLjQyLDI5OTUuNDNaIi8+CiAgICAgICAgICAgIDwvZz4KICAgICAgICA8L2c+CiAgICAgICAgPGc+CiAgICAgICAgICAgIDxnIHRyYW5zZm9ybT0ibWF0cml4KDAuMDg0NDk1NCwwLDAsMC4wODQ0OTU0LDE3MzEuODUsOTE3LjIxKSI+CiAgICAgICAgICAgICAgICA8cGF0aCBkPSJNMTkxMy40MiwyOTk1LjQzTDEyNTUuNzQsMjk5NS40M0wxMDg2Ljk0LDMxMTEuNDZMMTA4Ni45NCwzMjE1LjAxTDE2OTIuNTIsMzIxNS4wMUwxOTEzLjQyLDMwNjIuMDVMMTkxMy40MiwyOTk1LjQzWiIgc3R5bGU9ImZpbGw6d2hpdGU7Ii8+CiAgICAgICAgICAgIDwvZz4KICAgICAgICAgICAgPGcgdHJhbnNmb3JtPSJtYXRyaXgoMC45Mzc1NTgsMCwwLDAuOTM3NTU4LC00NzYwLjU0LC00MDgzLjg4KSI+CiAgICAgICAgICAgICAgICA8cGF0aCBkPSJNNzIwMi4xMiw1NjcxLjYzTDcyMDIuMTIsNTY4MC45TDcxNjMuNiw1NzIzLjM0TDcyNDAuODksNTgxOC43Mkw3MjQwLjg5LDU4MjcuOTlMNzIxMy40Myw1ODI3Ljk5TDcxMzkuNTMsNTczNy4wN0w3MTA0LjYxLDU3MzcuMDdMNzEwNC42MSw1ODI3Ljk5TDcwNzcuMzIsNTgyNy45OUw3MDc3LjMyLDU2MjMuOTFMNzEwNC42MSw1NjIzLjkxTDcxMDQuNjEsNTcwOS42MUw3MTM5LjUzLDU3MDkuNjFMNzE3NC42Niw1NjcxLjYzTDcyMDIuMTIsNTY3MS42M1oiIHN0eWxlPSJmaWxsOndoaXRlO2ZpbGwtcnVsZTpub256ZXJvOyIvPgogICAgICAgICAgICA8L2c+CiAgICAgICAgPC9nPgogICAgPC9nPgo8L3N2Zz4K
[Workoho-url]: https://workoho.com/
