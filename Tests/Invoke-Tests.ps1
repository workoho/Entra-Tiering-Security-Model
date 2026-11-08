# Installs Pester if needed and runs the tests in this folder.
# The CI workflow starts it with both Windows PowerShell 5.1 (powershell) and PowerShell 7 (pwsh).
param(
    [string] $PesterVersion = '5.8.0'
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name Pester | Where-Object { $_.Version -eq [Version] $PesterVersion })) {
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force | Out-Null
    }
    Install-Module -Name Pester -RequiredVersion $PesterVersion -Scope CurrentUser -Force -SkipPublisherCheck
}
Import-Module -Name Pester -RequiredVersion $PesterVersion

"PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition)), Pester $PesterVersion"
$config = New-PesterConfiguration
$config.Run.Path = $PSScriptRoot
$config.Run.Exit = $true
$config.Output.Verbosity = 'Detailed'
Invoke-Pester -Configuration $config
