# Checks the runbooks against Windows PowerShell 5.1, the runtime in Azure Automation: syntax, commands, parameters
# and .NET types, with the compatibility profiles that PSScriptAnalyzer ships. The tests are left out, because they
# run with Pester 5 while the 5.1 profile knows only the built-in Pester 3.4.
# A finding that does not apply, such as a call in a branch that runs only on PowerShell 7, goes into
# Compatibility.Accepted.psd1 with its reason, and so do files that another repository checks.
param(
    [string] $Path = (Join-Path $PSScriptRoot '../Runbooks'),
    [string] $AnalyzerVersion = '1.25.0'
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer | Where-Object { $_.Version -eq [Version] $AnalyzerVersion })) {
    Install-Module -Name PSScriptAnalyzer -RequiredVersion $AnalyzerVersion -Scope CurrentUser -Force
}
Import-Module -Name PSScriptAnalyzer -RequiredVersion $AnalyzerVersion

$profile51 = 'win-8_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework'
$settings = @{
    IncludeRules = 'PSUseCompatibleSyntax', 'PSUseCompatibleCommands', 'PSUseCompatibleTypes'
    Rules        = @{
        PSUseCompatibleSyntax   = @{ Enable = $true; TargetVersions = @('5.1') }
        PSUseCompatibleCommands = @{ Enable = $true; TargetProfiles = @($profile51) }
        PSUseCompatibleTypes    = @{ Enable = $true; TargetProfiles = @($profile51) }
    }
}
$exceptions = Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot 'Compatibility.Accepted.psd1')
$accepted = @($exceptions.Accepted)
$excludedFiles = @($exceptions.ExcludeFiles)

$files = Get-ChildItem -Path $Path -Recurse -Filter '*.ps1' | Where-Object {
    $name = $_.Name
    -not ($excludedFiles | Where-Object { $name -like $_ })
}
$findings = @($files | ForEach-Object { Invoke-ScriptAnalyzer -Path $_.FullName -Settings $settings } | Where-Object {
        $finding = $_
        -not ($accepted | Where-Object { $finding.ScriptName -eq $_.Script -and $finding.RuleName -eq $_.Rule -and $finding.Message -like $_.Message })
    })
foreach ($finding in $findings) {
    "$($finding.ScriptName):$($finding.Line): $($finding.RuleName): $($finding.Message)"
}
"$($findings.Count) compatibility findings for Windows PowerShell 5.1"
if ($findings.Count -gt 0) { exit 1 }
