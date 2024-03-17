@{
    # Use Severity when you want to limit the generated diagnostic records to a
    # subset of: Error, Warning and Information.
    # Uncomment the following line if you only want Errors and Warnings but
    # not Information diagnostic records.
    Severity       = @('Error', 'Warning')

    # Use IncludeRules when you want to run only a subset of the default rule set.
    #IncludeRules = @('PSAvoidDefaultValueSwitchParameter',
    #                 'PSMissingModuleManifestField',
    #                 'PSReservedCmdletChar',
    #                 'PSReservedParams',
    #                 'PSShouldProcess',
    #                 'PSUseApprovedVerbs',
    #                 'PSUseDeclaredVarsMoreThanAssigments')

    # Use ExcludeRules when you want to run most of the default set of rules except
    # for a few rules you wish to "exclude".  Note: if a rule is in both IncludeRules
    # and ExcludeRules, the rule will be excluded.
    #ExcludeRules = @('PSAvoidUsingWriteHost','PSMissingModuleManifestField')

    CustomRulePath = @(
        # Path to the custom rule module
        '.vscode/PSScriptAnalyzerCustomRules.ps1'
    )

    # You can use the following entry to supply parameters to rules that take parameters.
    # For instance, the PSAvoidUsingCmdletAliases rule takes a whitelist for aliases you
    # want to allow.
    Rules          = @{
        # Do not flag 'cd' alias.
        PSAvoidUsingCmdletAliases = @{Whitelist = @('cd') }

        # Check if your script uses cmdlets that are compatible with the following platforms
        PSUseCompatibleCmdlets    = @{
            Compatibility = @(
                'desktop-5.1.14393.206-windows'
                'core-6.1.0-linux'
                'core-6.1.0-macos'
                'core-6.1.0-windows'
            )
        }

        PSUseCompatibleSyntax     = @{
            # This turns the rule on (setting it to false will turn it off)
            Enable         = $true

            # List the targeted versions of PowerShell here
            TargetVersions = @(
                '5.1'   # Runbooks must work with PS 5.1
                '7.2'
            )
        }
    }
}
