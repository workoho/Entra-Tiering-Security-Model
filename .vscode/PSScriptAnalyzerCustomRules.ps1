# Custom rule to check for usage of Join-Path
function PSScriptAnalyzer_CustomRule_JoinPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.ScriptBlockAst] $Ast
    )

    # Check for usage of Join-Path
    $findings = $Ast.FindAll({
            param($node)

            # Check for usage of Join-Path with more than two arguments
            if ($node.CommandElements[0].Value -eq 'Join-Path' -and $node.CommandElements.Count -gt 2) {
                $violationMessage = "Join-Path in PowerShell 5.1 can only handle two paths."
                $extent = $node.Extent
                $diagnosticRecord = New-Object -TypeName Microsoft.Windows.PSScriptAnalyzer.Generic.DiagnosticRecord -ArgumentList $violationMessage, $extent, 'CustomRule', 'Warning', $null, $null
                return $diagnosticRecord
            }

            return $null
        }, $true)

    return $findings
}

function PSScriptAnalyzer_CustomRule_SplitPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.ScriptBlockAst] $Ast
    )

    # Check for usage of Split-Path
    $findings = $Ast.FindAll({
            param($node)

            # Check for usage of Split-Path with -LeafBase parameter
            if ($node.CommandElements[0].Value -eq 'Split-Path' -and $node.CommandElements.Value -contains '-LeafBase') {
                $violationMessage = "Split-Path in PowerShell 5.1 does not support the -LeafBase parameter."
                $extent = $node.Extent
                $diagnosticRecord = New-Object -TypeName Microsoft.Windows.PSScriptAnalyzer.Generic.DiagnosticRecord -ArgumentList $violationMessage, $extent, 'CustomRule', 'Warning', $null, $null
                return $diagnosticRecord
            }

            return $null
        }, $true)

    return $findings
}

function PSScriptAnalyzer_CustomRule_GetChildItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.ScriptBlockAst] $Ast
    )

    # Check for usage of Get-ChildItem
    $findings = $Ast.FindAll({
            param($node)

            # Check for usage of Get-ChildItem with -Depth parameter
            if ($node.CommandElements[0].Value -eq 'Get-ChildItem' -and $node.CommandElements.Value -contains '-Depth') {
                $violationMessage = "Get-ChildItem in PowerShell 5.1 does not support the -Depth parameter."
                $extent = $node.Extent
                $diagnosticRecord = New-Object -TypeName Microsoft.Windows.PSScriptAnalyzer.Generic.DiagnosticRecord -ArgumentList $violationMessage, $extent, 'CustomRule', 'Warning', $null, $null
                return $diagnosticRecord
            }

            return $null
        }, $true)

    return $findings
}

function PSScriptAnalyzer_CustomRule_ConvertToJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.ScriptBlockAst] $Ast
    )

    # Check for usage of ConvertTo-Json
    $findings = $Ast.FindAll({
            param($node)

            # Check for usage of ConvertTo-Json with -AsHashtable parameter
            if ($node.CommandElements[0].Value -eq 'ConvertTo-Json' -and $node.CommandElements.Value -contains '-AsHashtable') {
                $violationMessage = "ConvertTo-Json in PowerShell 5.1 does not support the -AsHashtable parameter."
                $extent = $node.Extent
                $diagnosticRecord = New-Object -TypeName Microsoft.Windows.PSScriptAnalyzer.Generic.DiagnosticRecord -ArgumentList $violationMessage, $extent, 'CustomRule', 'Warning', $null, $null
                return $diagnosticRecord
            }

            return $null
        }, $true)

    return $findings
}

function PSScriptAnalyzer_CustomRule_InvokeRestMethod {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.ScriptBlockAst] $Ast
    )

    # Check for usage of Invoke-RestMethod
    $findings = $Ast.FindAll({
            param($node)

            # Check for usage of Invoke-RestMethod with -SkipCertificateCheck parameter
            if ($node.CommandElements[0].Value -eq 'Invoke-RestMethod' -and $node.CommandElements.Value -contains '-SkipCertificateCheck') {
                $violationMessage = "Invoke-RestMethod in PowerShell 5.1 does not support the -SkipCertificateCheck parameter."
                $extent = $node.Extent
                $diagnosticRecord = New-Object -TypeName Microsoft.Windows.PSScriptAnalyzer.Generic.DiagnosticRecord -ArgumentList $violationMessage, $extent, 'CustomRule', 'Warning', $null, $null
                return $diagnosticRecord
            }

            return $null
        }, $true)

    return $findings
}

function PSScriptAnalyzer_CustomRule_NewObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.ScriptBlockAst] $Ast
    )

    # Check for usage of New-Object
    $findings = $Ast.FindAll({
            param($node)

            # Check for usage of New-Object with -Property parameter
            if ($node.CommandElements[0].Value -eq 'New-Object' -and $node.CommandElements.Value -contains '-Property') {
                # Get the argument to the -Property parameter
                $propertyArgument = $node.CommandElements[$node.CommandElements.IndexOf('-Property') + 1]

                # Check if the argument is a hashtable or psobject
                if ($propertyArgument.Type -is [System.Management.Automation.Language.HashtableAst] -or $propertyArgument.Type -is [System.Management.Automation.Language.PSObjectAst]) {
                    # Check if the hashtable or psobject contains properties with values of type psobject
                    foreach ($pair in $propertyArgument.Pairs) {
                        if ($pair.Value.Type -is [System.Management.Automation.Language.PSObjectAst]) {
                            $violationMessage = "New-Object in PowerShell 5.1 does not support the -Property parameter with a hashtable or psobject that contains properties with values of type psobject."
                            $extent = $node.Extent
                            $diagnosticRecord = New-Object -TypeName Microsoft.Windows.PSScriptAnalyzer.Generic.DiagnosticRecord -ArgumentList $violationMessage, $extent, 'PSScriptAnalyzer_CustomRule_NewObject', 'Warning', $null, $null
                            return $diagnosticRecord
                        }
                    }
                }
            }

            return $null
        }, $true)

    return $findings
}

# Export the functions as a rule for PSScriptAnalyzer
Export-ModuleMember -Function PSScriptAnalyzer_CustomRule_JoinPath
Export-ModuleMember -Function PSScriptAnalyzer_CustomRule_SplitPath
Export-ModuleMember -Function PSScriptAnalyzer_CustomRule_GetChildItem
Export-ModuleMember -Function PSScriptAnalyzer_CustomRule_ConvertToJson
Export-ModuleMember -Function PSScriptAnalyzer_CustomRule_InvokeRestMethod
Export-ModuleMember -Function PSScriptAnalyzer_CustomRule_NewObject
