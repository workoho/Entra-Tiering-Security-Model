<#PSScriptInfo
.VERSION 1.0.1
.GUID b5e78940-5e2f-427d-87a1-c1630ed8c3da
.AUTHOR Julian Pawlowski
.COMPANYNAME Workoho GmbH
.COPYRIGHT © 2024 Workoho GmbH
.TAGS
.LICENSEURI https://github.com/workoho/AzAuto-Project.tmpl/LICENSE.txt
.PROJECTURI https://github.com/workoho/AzAuto-Project.tmpl
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
    Version 1.0.1 (2024-05-25)
    - Use Write-Host to avoid output to the pipeline, avoiding interpretation as shell commands
    - Set error code when exiting with error
#>

<#
.SYNOPSIS
    Clone the Azure Automation Common Runbook Framework repository and invoke its setup scripts.

.DESCRIPTION
    Make sure that a clone of the Azure Automation Common Runbook Framework repository
    exists in parallel to this project repository. For example:

        C:\Developer\AzAuto-Project.tmpl
        C:\Developer\AzAuto-Common-Runbook-FW

    After this, invoke this script from the setup folder of the parent repository:

        C:\Developer\AzAuto-Common-Runbook-FW\setup\AzAutoFWProject\Update-AzAutoFWProject.ps1

    You may run this script at any time to update the project setup.
    When opening the project in Visual Studio Code, a task to run this script is already
    configured in .vscode\tasks.json.

.EXAMPLE
    Update-AzAutoFWProject.ps1
#>

[CmdletBinding()]
param(
    [switch]$VsCodeTask
)

Write-Verbose "---START of $((Get-Item $PSCommandPath).Name), $((Test-ScriptFileInfo $PSCommandPath | Select-Object -Property Version, Guid | & { process{$_.PSObject.Properties | & { process{$_.Name + ': ' + $_.Value} }} }) -join ', ') ---"

$commonParameters = 'Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction', 'ErrorVariable', 'WarningVariable', 'InformationVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable', 'WhatIf'
$commonBoundParameters = $PSBoundParameters.Keys | Where-Object { $_ -in $commonParameters } | ForEach-Object { @{ $_ = $PSBoundParameters[$_] } }

#region Read Project Configuration
$projectDir = (Get-Item $PSScriptRoot).Parent.Parent.FullName
$configDir = Join-Path $projectDir (Join-Path 'config' 'AzAutoFWProject')
$configName = 'AzAutoFWProject.psd1'
$config = $null
$configScriptPath = Join-Path $projectDir (Join-Path 'scripts' (Join-Path 'AzAutoFWProject' 'Get-AzAutoFWConfig.ps1'))

Get-ChildItem -Path $configDir -File -Filter '*.template.*' -Recurse | & {
    process {
        $targetPath = $_.FullName -replace '\.template\.(.+)$', '.$1'
        if (-not (Test-Path $targetPath)) {
            Write-Verbose "Copying $_ to $targetPath"
            Copy-Item -Path $_.FullName -Destination $targetPath -Force
        }
    }
}

if (
    (Test-Path $configScriptPath -PathType Leaf) -and
    (
        ((Get-Item $configScriptPath).LinkType -ne "SymbolicLink") -or
        (
            Test-Path -LiteralPath (
                Resolve-Path -Path (
                    Join-Path -Path (Split-Path $configScriptPath) -ChildPath (
                        Get-Item -LiteralPath $configScriptPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Target
                    )
                ) -ErrorAction SilentlyContinue
            ) -PathType Leaf -ErrorAction SilentlyContinue
        )
    )
) {
    Write-Verbose 'Found parent update script.'
    if ($commonBoundParameters) {
        $config = & $configScriptPath -ConfigDir $configDir -ConfigName $configName @commonBoundParameters
    }
    else {
        $config = & $configScriptPath -ConfigDir $configDir -ConfigName $configName
    }
}
else {
    # This will only run when the project is not yet configured.
    Write-Verbose 'Missing parent update script: Reading minimum configuration for project initialization.'
    $configPath = Join-Path $configDir $configName
    $config = $null
    try {
        $config = Import-PowerShellDataFile -Path $configPath -ErrorAction Stop | & {
            process {
                $_.Keys | Where-Object { $_ -notin ('ModuleVersion', 'Author', 'Description', 'PrivateData') } | & {
                    process {
                        $_.Remove($_)
                    }
                }
                $_.PrivateData.Remove('PSData')
                $local:configData = $_
                $_.PrivateData.GetEnumerator() | & {
                    process {
                        $configData.Add($_.Key, $_.Value)
                    }
                }
                $_.Remove('PrivateData')
                $_
            }
        }
    }
    catch {
        Write-Error "Failed to read configuration file ${configPath}: $_" -ErrorAction Stop
        exit 1
    }
    $config.Project = @{ Directory = $projectDir }
    $config.Config = @{ Directory = $configDir; Name = $configName; Path = $configPath }
    $config.IsAzAutoFWProject = $true
}

if (-not $config.GitRepositoryUrl) { Write-Error "config.GitRepositoryUrl is missing in $configPath"; exit 1 }
if (-not $config.GitReference) { Write-Error "config.GitReference is missing in $configPath"; exit 1 }
#endregion

#region Clone repository if not exists
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Error "Git is not installed on this system."
    exit 1
}

$AzAutoFWDir = Join-Path (Get-Item $PSScriptRoot).Parent.Parent.Parent.FullName (
    [IO.Path]::GetFileNameWithoutExtension((Split-Path $config.GitRepositoryUrl -Leaf))
).TrimEnd('.git')

if (-Not (Test-Path (Join-Path $AzAutoFWDir '.git') -PathType Container)) {
    try {
        Write-Host "Cloning $($config.GitRepositoryUrl) to $AzAutoFWDir"
        $output = git clone --quiet $config.GitRepositoryUrl $AzAutoFWDir 2>&1
        if ($LASTEXITCODE -ne 0) { Throw "Failed to clone repository: $output" }
    }
    catch {
        Write-Error $_
        exit 1
    }
}
#endregion

#region Invoke sibling script from parent repository
try {
    Join-Path $AzAutoFWDir (Join-Path 'scripts' (Join-Path 'AzAutoFWProject' (Split-Path $PSCommandPath -Leaf))) | & {
        process {
            if (Test-Path $_ -PathType Leaf) {
                if ($commonBoundParameters) {
                    & $_ -ChildConfig $config -VsCodeTask:$VsCodeTask @commonBoundParameters
                }
                else {
                    & $_ -ChildConfig $config -VsCodeTask:$VsCodeTask
                }
            }
            else {
                Write-Error "Could not find $_" -ErrorAction Stop
            }
        }
    }
}
catch {
    Write-Error $_
    exit 1
}
#endregion

Write-Verbose "-----END of $((Get-Item $PSCommandPath).Name) ---"
