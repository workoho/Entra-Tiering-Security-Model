@{
    ModuleVersion = '0.0.0'     # Ignored, only to have a valid psd1 file format.
    Author        = 'Azure Automation Common Runbook Framework'
    Description   = 'Template for machine local configuration items that shall not be added to the Git repository.'
    PrivateData   = @{

        # Configure the Automation Account to be created or updated
        AutomationAccount  = @{
            # Can be any name you want, but must be unique within the Azure tenant.
            # Following the naming convention <SubscriptionName>-<Region>-aa001 is recommended.
            Name              = 'prodsub-germanywestcentral-aa001'

            # The plan determines the pricing tier of the automation account.
            # 'Free' is limited to 500 minutes per month, 'Basic' is limited to 10,000 minutes per month.
            Plan              = 'Basic'

            # The location of the automation account.
            # If the location is not set, the location of the resource group will be used.
            Location          = ''

            # The resource group should already exist, otherwise it will be created.
            # When following the naming convention <SubscriptionName>-<Region>-automation-rg,
            # the <Region> will be used for the location of the resource group, if the Location property is not set.
            ResourceGroupName = 'prodsub-germanywestcentral-automation-rg'

            # The subscription ID and tenant ID can be found in the Azure portal.
            SubscriptionId    = '00000000-0000-0000-0000-000000000000'
            TenantId          = '00000000-0000-0000-0000-000000000000'

            # Azure tags to be added to the automation account (once during creation only).
            # If the resource group does not exist yet and is created by this script,
            # the tags will be added to the resource group as well.
            Tag               = @{
                Application = 'CloudAdmin'          # could be your project or application name
                Environment = 'Production'          # Production, Staging, Development, etc.
                Owner       = 'TeamA'               # Team or owner of the resource, should be an email address
            }
        }

        # If you would like to set any values for Automation Variables, you can do so here.
        AutomationVariable = @(
            # # EXAMPLE:
            # @{
            #     Name  = 'AV_ProjectName_VariableName'
            #     Value = ''
            # }
        )

        # Configure Managed Identities for the Azure Automation Account.
        ManagedIdentity    = @(
            # You might move Managed Identity defintions from the public AzAutoFWProject.psd1
            # to this local configuration file for improved security.
        )
    }
}
