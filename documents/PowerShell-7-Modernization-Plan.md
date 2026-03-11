# PowerShell 7 Modernization Plan

> Entra Tiering Security Model & AzAuto-Common-Runbook-FW\
> Erstellt: 2026-03-11 | Status: Entwurf

---

## Ausgangslage

### Zwei Repository-Verbund

| Repository | Zweck | Aktueller Stand |
|---|---|---|
| `Entra-Tiering-Security-Model` | Cloud Admin Tiering – Business-Logik | 5 Runbooks, PS 5.1 primär |
| `AzAuto-Common-Runbook-FW` | Framework – generische Azure/Graph-Utilities | ~15+ Common_* Skripte, PS 5.1 primär |

### Architekturprobleme der aktuellen Implementierung

1. **Dot-Sourcing statt Modulsystem** – Runbooks laden andere Runbooks über `.` (Dot-Source), was Laufzeitabhängigkeiten erzeugt und keinen echten Scope-Schutz bietet.
2. **Symlink-Magie** – Das Framework wird per Git-Clone + Symlinks ins Projekt hineingezogen (`Update-AzAutoFWProject.ps1`). Funktioniert nur auf Entwicklermaschinen mit speziellen Rechten.
3. **PS 5.1 Einschränkungen** – 7 eigene PSScriptAnalyzer-Regeln dokumentieren die Workarounds; `Join-Path` mit 3+ Pfadsegmenten, `ConvertFrom-Json -AsHashtable`, `Invoke-RestMethod -SkipCertificateCheck` etc. sind verboten.
4. **Azure Automation Variablen als einzige Konfigurationsquelle** – Weder versioniert noch deploybar ohne lokales Skript.
5. **Interrunbook-Abhängigkeiten** – `CloudAdmin_3100` ruft `Common_0001` auf, `Common_0002` ruft `Common_0001` auf. Kein Runbook steht für sich allein.
6. **Kein Infrastructure-as-Code** – Die Azure-Ressourcen (Automation Account, Variablen, Runbooks, Schedules, RBAC) werden manuell oder per lokalem Skript erstellt.

---

## Zielarchitektur

```
┌─────────────────────────────────────────────────────────────────┐
│  GitHub Repository: Entra-Tiering-Security-Model                │
│                                                                  │
│  ┌─────────────────────┐   ┌──────────────────────────────────┐ │
│  │  /bicep/            │   │  /src/Workoho.CloudAdmin/        │ │
│  │  Infrastruktur-     │   │  PowerShell 7 Modul              │ │
│  │  Templates          │   │  (enthält Framework + Business)   │ │
│  └────────┬────────────┘   └──────────────┬───────────────────┘ │
│           │ az deployment group create    │ Import-Module        │
│           ▼                               ▼                      │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  Azure Automation Account                                   │ │
│  │  Runtime: PowerShell 7.4                                    │ │
│  │                                                             │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │ │
│  │  │ Runbook:     │  │ Runbook:     │  │ Runbook:         │  │ │
│  │  │ New-         │  │ Get-Cloud    │  │ Invoke-Lifecycle  │  │ │
│  │  │ CloudAdmin   │  │ AdminAccts   │  │ Management       │  │ │
│  │  │ Account      │  │              │  │                  │  │ │
│  │  │ (standalone) │  │ (standalone) │  │ (standalone)     │  │ │
│  │  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘  │ │
│  │         │                 │                    │            │ │
│  │         └─────────────────┴────────────────────┘            │ │
│  │                           │                                 │ │
│  │                    Import-Module                            │ │
│  │                           │                                 │ │
│  │              ┌────────────▼───────────────┐                 │ │
│  │              │  Workoho.CloudAdmin         │                 │ │
│  │              │  (Runtime Environment)      │                 │ │
│  │              └────────────────────────────┘                 │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Kernprinzipien

1. **Jedes Runbook ist autark** – kein Dot-Sourcing, kein Child-Runbook-Call, nur `Import-Module`
2. **Modul enthält alle Logik** – Business-Logik + Framework-Utilities in einem paketiertem PS7-Modul
3. **Bicep deployt alles** – Automation Account, Runtime, Modul, Runbooks, Variablen, RBAC, Schedules
4. **Manueller Deployment-Trigger** – `az deployment group create` vom Operator ausgeführt
5. **PowerShell 7.4** als einziges Target – keine PS 5.1 Kompatibilitätsschichten mehr

---

## Repository-Struktur (Ziel)

### Entra-Tiering-Security-Model

```
/
├── bicep/
│   ├── main.bicep                          # Einstiegspunkt
│   ├── main.bicepparam.example             # Parameter-Template für Benutzer
│   └── modules/
│       ├── automation-account.bicep        # Automation Account Ressource
│       ├── runtime-environment.bicep       # PS 7.4 Runtime + Modul-Upload
│       ├── runbooks.bicep                  # Runbook-Deployment
│       ├── automation-variables.bicep      # Konfigurations-Variablen
│       ├── role-assignments.bicep          # Managed Identity RBAC
│       └── schedules.bicep                 # Automation Schedules
│
├── src/
│   └── Workoho.CloudAdmin/
│       ├── Workoho.CloudAdmin.psd1         # Modulmanifest
│       ├── Workoho.CloudAdmin.psm1         # Root-Loader (dot-sourced alle Public/)
│       ├── Public/                         # Exportierte Funktionen
│       │   ├── Connect-MgGraphAutomation.ps1
│       │   ├── Connect-ExchangeOnlineAutomation.ps1
│       │   ├── Import-AutomationVariable.ps1
│       │   ├── Invoke-MgGraphRequest.ps1
│       │   ├── Confirm-MgAppPermission.ps1
│       │   ├── Confirm-MgDirectoryRoleAssignment.ps1
│       │   ├── Find-MgUserWithSoftDeleted.ps1
│       │   ├── Get-CloudAdminConfiguration.ps1
│       │   ├── Get-CloudAdminAccountsByPrimary.ps1
│       │   ├── Get-PrimaryAccountsByCloudAdmin.ps1
│       │   ├── New-CloudAdministratorAccount.ps1
│       │   └── Invoke-CloudAdminLifecycle.ps1
│       └── Private/                        # Interne Hilfsfunktionen
│           ├── Resolve-UserIdentity.ps1
│           ├── ConvertTo-FlatObject.ps1
│           └── Write-AutomationOutput.ps1
│
├── Runbooks/
│   ├── New-CloudAdministratorAccount.ps1   # Dünner Wrapper → ruft Modul-Funktion
│   ├── Get-CloudAdminAccounts.ps1
│   ├── Get-PrimaryAccounts.ps1
│   └── Invoke-AccountLifecycle.ps1
│
├── scripts/
│   ├── Build-Module.ps1                    # Erstellt Modul-ZIP für Bicep-Deployment
│   └── Deploy-Infrastructure.ps1           # Orchestriert Build + az deployment
│
├── tests/
│   ├── Unit/                               # Pester Unit-Tests pro Modul-Funktion
│   └── Integration/                        # Tests gegen echte Azure-Umgebung
│
└── .vscode/
    ├── PSScriptAnalyzerSettings.psd1       # Aktualisiert: nur noch PS7-Regeln
    └── extensions.json
```

### AzAuto-Common-Runbook-FW

Das Framework wird als Quell-Repository umgebaut: Die Common_* Skripte werden als Basis für die `Workoho.CloudAdmin`-Modulfunktionen in `Public/` dienen (und können als Git-Submodule oder direkte Inhalte übernommen werden, je nach Entscheidung). Das Framework-Repo selbst muss nicht mehr deploybar sein, da die Deployment-Verantwortung bei den jeweiligen Projekten liegt.

---

## PowerShell-Modul: `Workoho.CloudAdmin`

### Modulmanifest (`Workoho.CloudAdmin.psd1`)

```powershell
@{
    ModuleVersion     = '2.0.0'
    GUID              = '<new-guid>'
    Author            = 'Julian Pawlowski'
    CompanyName       = 'Workoho GmbH'
    PowerShellVersion = '7.4'
    RequiredModules   = @(
        @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.0.0' }
        @{ ModuleName = 'Microsoft.Graph.Users';          ModuleVersion = '2.0.0' }
        @{ ModuleName = 'Microsoft.Graph.Groups';         ModuleVersion = '2.0.0' }
        @{ ModuleName = 'Microsoft.Graph.Beta.Identity.DirectoryManagement'; ModuleVersion = '2.0.0' }
        @{ ModuleName = 'ExchangeOnlineManagement';       ModuleVersion = '3.0.0' }
        @{ ModuleName = 'Az.Accounts';                    ModuleVersion = '3.0.0' }
    )
    FunctionsToExport = @(
        'Connect-MgGraphAutomation'
        'Connect-ExchangeOnlineAutomation'
        'Import-AutomationVariable'
        'Invoke-MgGraphRequest'
        'Confirm-MgAppPermission'
        'Confirm-MgDirectoryRoleAssignment'
        'Find-MgUserWithSoftDeleted'
        'Get-CloudAdminConfiguration'
        'Get-CloudAdminAccountsByPrimary'
        'Get-PrimaryAccountsByCloudAdmin'
        'New-CloudAdministratorAccount'
        'Invoke-CloudAdminLifecycle'
    )
}
```

### PS7-spezifische Modernisierungen

| Altes Muster (PS 5.1) | Neues Muster (PS 7.4) |
|---|---|
| `if ($x -ne $null) { $x } else { 'default' }` | `$x ?? 'default'` |
| `if ($cond) { 'yes' } else { 'no' }` | `$cond ? 'yes' : 'no'` |
| `Join-Path $a (Join-Path $b $c)` | `Join-Path $a $b $c` |
| `ConvertFrom-Json` + manuelle Hashtable | `ConvertFrom-Json -AsHashtable` |
| `Invoke-WebRequest -UseBasicParsing` | `Invoke-WebRequest` (kein Flag nötig) |
| `foreach ($x in $list) { ... }` (sequenziell) | `$list \| ForEach-Object -Parallel { ... }` |
| Manuelles `$Error[0]` auswerten | `Get-Error` für strukturierte Fehleranalyse |
| `[System.Collections.ArrayList]` | Native `[List[T]]` oder `@()` mit `+=` |
| Try/Catch mit `$_.Exception.Message` | Strukturierte `ErrorRecord`-Auswertung |
| `Write-Output` für Logging | `$PSStyle`-basierte farbige Ausgabe |
| PS 5.1 Custom ScriptAnalyzer-Regeln (7 Stück) | Alles weg – alle PS6+ Features erlaubt |

---

## Bicep-Infrastruktur

### Deployment-Ablauf (manuell)

```
Operator
   │
   ├─ 1. Edit: main.bicepparam (lokale Kopie aus main.bicepparam.example)
   │
   ├─ 2. Run: ./scripts/Build-Module.ps1
   │          └─ Erstellt: ./build/Workoho.CloudAdmin.zip
   │
   └─ 3. Run: az deployment group create \
                --resource-group <rg> \
                --template-file bicep/main.bicep \
                --parameters bicep/main.bicepparam
                # Bicep-Deployment lädt das Modul-ZIP via deploymentScript hoch
```

### `main.bicep` – Überblick

```bicep
// main.bicep
targetScope = 'resourceGroup'

param automationAccountName string
param location string = resourceGroup().location
param runtimeEnvironmentName string = 'PS74-CloudAdmin'

// 1. Automation Account
module automationAccount 'modules/automation-account.bicep' = { ... }

// 2. Runtime Environment (PS 7.4) + Modul-Upload
module runtimeEnv 'modules/runtime-environment.bicep' = {
  dependsOn: [ automationAccount ]
  params: {
    moduleZipBase64: loadFileAsBase64('../build/Workoho.CloudAdmin.zip')
    // Alternativ: SAS-URL zu einem Storage Blob
  }
}

// 3. Automation Variables (Konfiguration)
module variables 'modules/automation-variables.bicep' = { ... }

// 4. Runbooks
module runbooks 'modules/runbooks.bicep' = {
  dependsOn: [ runtimeEnv ]
  ...
}

// 5. Managed Identity RBAC
module rbac 'modules/role-assignments.bicep' = { ... }

// 6. Schedules
module schedules 'modules/schedules.bicep' = {
  dependsOn: [ runbooks ]
  ...
}
```

### `modules/runtime-environment.bicep`

```bicep
// Erstellt Runtime Environment mit PS 7.4 und lädt das Modul hoch
resource runtimeEnv 'Microsoft.Automation/automationAccounts/runtimeEnvironments@2023-11-01' = {
  name: runtimeEnvironmentName
  properties: {
    runtime: {
      language: 'PowerShell'
      version: '7.4'
    }
    defaultPackages: {
      // Az.Accounts, Microsoft.Graph etc. werden automatisch erkannt
    }
  }
}

// Modul als Custom Package hochladen
resource modulePackage 'Microsoft.Automation/automationAccounts/runtimeEnvironments/packages@2023-11-01' = {
  name: 'Workoho.CloudAdmin'
  parent: runtimeEnv
  properties: {
    contentLink: {
      uri: moduleContentUri     // SAS-URL zum ZIP oder deploymentScript-Output
    }
  }
}
```

**Hinweis:** Da `loadFileAsBase64()` in Bicep auf ~4 MB begrenzt ist und ein Modul-ZIP größer sein kann, empfiehlt sich folgender Ansatz:

1. Bicep erstellt erst einen Storage Account (temporär, nur für das Deployment)
2. Ein `Microsoft.Resources/deploymentScripts`-Block lädt das Modul-ZIP hoch und gibt die SAS-URL zurück
3. Das `runtimeEnvironments/packages`-Modul referenziert diese URL

### `modules/automation-variables.bicep`

Alle bisherigen Azure Automation Variablen aus `AzAutoFWProject.psd1` werden als Bicep-Ressourcen abgebildet:

```bicep
var variables = [
  { name: 'AV_CloudAdmin_RestrictedAdminUnitId',    value: restrictedAdminUnitId,  encrypted: false }
  { name: 'AV_CloudAdminTier0_GroupId_Tier',        value: tier0GroupId,           encrypted: false }
  { name: 'AV_CloudAdminTier0_LicenseGroupId',      value: tier0LicenseGroupId,    encrypted: false }
  // ... alle ~18 Variablen
]

resource automationVars 'Microsoft.Automation/automationAccounts/variables@2023-11-01' = [
  for v in variables: {
    name: v.name
    properties: {
      value: '"${v.value}"'
      isEncrypted: v.encrypted
    }
  }
]
```

### `modules/role-assignments.bicep`

Die Managed Identity des Automation Accounts benötigt Graph API App Roles und Azure RBAC:

```bicep
// Azure RBAC - z.B. Storage Blob Data Contributor für CSV-Export
resource storageRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = { ... }

// Graph API App Roles müssen über Microsoft Graph API gesetzt werden.
// Da Bicep keine nativen Graph-Ressourcen unterstützt, verwenden wir deploymentScript:
resource graphPermissions 'Microsoft.Resources/deploymentScripts@2023-08-01' = {
  name: 'Set-GraphPermissions'
  kind: 'AzurePowerShell'
  properties: {
    azPowerShellVersion: '12.0'
    scriptContent: '''
      # Graph App Role Assignments für Managed Identity
      Connect-MgGraph -Identity
      $sp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
      # ... AppRoles zuweisen
    '''
  }
}
```

---

## Neue Runbook-Struktur

### Runbook-Template (Prinzip)

Jedes Runbook folgt exakt diesem Muster – keine dot-sourcing, keine Common-Skript-Abhängigkeiten:

```powershell
#Requires -Modules @{ ModuleName = 'Workoho.CloudAdmin'; ModuleVersion = '2.0.0' }
#Requires -PSEdition Core

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string[]] $ReferralUserId,

    [ValidateRange(0, 2)]
    [int[]] $Tier,

    [switch] $OutJson,
    [switch] $OutCsv
)

# Authentifizierung (eine Zeile – alles im Modul)
Connect-MgGraphAutomation -Scopes @('User.Read.All', 'Directory.Read.All')
Import-AutomationVariable   # Liest alle AV_* Variablen aus dem Automation Account

# Business Logic (eine Zeile – alles im Modul)
$result = Get-CloudAdminAccountsByPrimary -ReferralUserId $ReferralUserId -Tier $Tier

# Output
if ($OutJson) { $result | ConvertTo-Json -Depth 10 }
elseif ($OutCsv) { $result | Export-CloudAdminCsv }
else { $result }
```

### Die 4 neuen Runbooks

| Runbook | Entspricht altem Skript | Ziel |
|---|---|---|
| `New-CloudAdministratorAccount.ps1` | `CloudAdmin_0100__New-CloudAdministrator-Account.ps1` | Account erstellen/aktualisieren |
| `Get-CloudAdminAccounts.ps1` | `CloudAdmin_0000__Common_0001__Get-CloudAdminAccountsByPrimaryAccount.ps1` | Lesezugriff / Export |
| `Get-PrimaryAccounts.ps1` | `CloudAdmin_0000__Common_0002__Get-PrimaryAccountsByCloudAdminAccount.ps1` | Reverse-Lookup / Export |
| `Invoke-AccountLifecycle.ps1` | `CloudAdmin_3100__Invoke-Scheduled-CloudAdministrator-AccountLifecycleManagement.ps1` | Lifecycle-Schedule |

**`Get-ConfigurationConstants` wird kein eigenes Runbook mehr** – es wird zur internen Modul-Funktion `Get-CloudAdminConfiguration`.

---

## Migrationspfad

### Phase 0 – Vorbereitung (beide Repos)

- [ ] Neues Branch-Schema festlegen (`main` statt `master`)
- [ ] `CLAUDE.md` anlegen mit Entwicklungskonventionen
- [ ] PSScriptAnalyzer-Konfiguration auf PS7-only umstellen (alle 7 Custom-Rules entfernen)
- [ ] Pester-Testinfrastruktur einrichten (Pester ≥ 5.x)
- [ ] AzAuto-Common-Runbook-FW: Entscheidung ob Git-Submodul oder Merge in dieses Repo
  - **Empfehlung**: Merge der Framework-Funktionen direkt in `Workoho.CloudAdmin/Public/` (kein separates Repo mehr nötig), da das Framework primär für dieses Projekt genutzt wird
  - Falls das Framework auch für andere Projekte genutzt werden soll: als separates NuGet-Paket publizieren

### Phase 1 – PowerShell-Modul anlegen

- [ ] `src/Workoho.CloudAdmin/` Verzeichnisstruktur erstellen
- [ ] `Workoho.CloudAdmin.psd1` Manifest erstellen (PS7.4, RequiredModules)
- [ ] `Workoho.CloudAdmin.psm1` Root-Loader erstellen

### Phase 2 – Framework-Funktionen migrieren

*Aus AzAuto-Common-Runbook-FW → `Public/` im neuen Modul*

- [ ] `Connect-MgGraphAutomation.ps1` – Authentifizierung gegen Graph via Managed Identity
  - PS7: keine `-UseBasicParsing` Workarounds
  - PS7: `??` für Scope-Defaults
- [ ] `Connect-ExchangeOnlineAutomation.ps1` – EXO-Verbindung
- [ ] `Import-AutomationVariable.ps1` – Azure Automation Variablen laden
  - Ersetzt `Common_0002__Import-AzAutomationVariableToPSEnv.ps1` + `Common_0000__Convert-PSEnvToPSScriptVariable.ps1`
  - Liest direkt in eine strukturierte Hashtable (kein Env-Var-Umweg)
- [ ] `Invoke-MgGraphRequest.ps1` – Graph API Wrapper mit Retry-Logic
- [ ] `Confirm-MgAppPermission.ps1` – App-Permission-Validierung
- [ ] `Confirm-MgDirectoryRoleAssignment.ps1` – Role-Assignment-Prüfung
- [ ] `Find-MgUserWithSoftDeleted.ps1` – Suche inkl. gelöschter Accounts

### Phase 3 – Business-Logik migrieren

*Aus vorhandenen Runbooks → `Public/` im neuen Modul*

- [ ] `Get-CloudAdminConfiguration.ps1` – Replaces `Get-ConfigurationConstants`
  - Gibt typisiertes `[CloudAdminConfig]` Objekt zurück (PS7 Class oder `[pscustomobject]`)
  - Alle 100+ Konstanten, aber strukturierter aufgebaut
  - Nutzt `Import-AutomationVariable` intern
- [ ] `Get-CloudAdminAccountsByPrimary.ps1` – Aus `Common_0001`
  - PS7: `ForEach-Object -Parallel` für Batch-Lookup
  - PS7: `ConvertFrom-Json -AsHashtable` für Graph-Responses
  - PS7: Ternary statt If/Else-Ketten
- [ ] `Get-PrimaryAccountsByCloudAdmin.ps1` – Aus `Common_0002`
  - Intern: ruft `Get-CloudAdminAccountsByPrimary` auf (kein Runbook-Dependency)
- [ ] `New-CloudAdministratorAccount.ps1` – Aus `CloudAdmin_0100` (~3000 Zeilen)
  - Aufteilen in logische Interne Hilfsfunktionen in `Private/`
  - PS7: Strukturierte Error-Records statt String-Matching
  - PS7: `$PSStyle` für Fortschrittsanzeige
- [ ] `Invoke-CloudAdminLifecycle.ps1` – Aus `CloudAdmin_3100`
  - PS7: `ForEach-Object -Parallel` für parallele Account-Verarbeitung

### Phase 4 – Runbooks schreiben

- [ ] 4 dünne Runbook-Wrapper erstellen (je ~30 Zeilen)
- [ ] Alle Runbooks validieren gegen PS7-Syntax

### Phase 5 – Bicep-Templates erstellen

- [ ] `bicep/main.bicep` Einstiegspunkt
- [ ] `bicep/modules/automation-account.bicep`
- [ ] `bicep/modules/runtime-environment.bicep` (PS 7.4)
- [ ] `bicep/modules/runbooks.bicep`
- [ ] `bicep/modules/automation-variables.bicep` (alle ~18 Variablen aus PSD1)
- [ ] `bicep/modules/role-assignments.bicep` (Azure RBAC + Graph Permissions via deploymentScript)
- [ ] `bicep/modules/schedules.bicep`
- [ ] `bicep/main.bicepparam.example`

### Phase 6 – Build & Deploy-Scripts

- [ ] `scripts/Build-Module.ps1` – Erstellt das Modul-ZIP
  - Lädt Abhängigkeiten herunter (via `Save-Module`)
  - Packt alles in ein ZIP mit korrekter Verzeichnisstruktur
  - Output: `build/Workoho.CloudAdmin.zip`
- [ ] `scripts/Deploy-Infrastructure.ps1` – Orchestriert den Deployment-Prozess
  - Ruft `Build-Module.ps1` auf
  - Optional: Lädt ZIP in temporären Storage-Blob hoch
  - Startet `az deployment group create`

### Phase 7 – Tests

- [ ] Pester Unit-Tests für jede Public-Funktion
- [ ] Integration-Test-Runbook für Smoke-Tests in Azure
- [ ] Bicep `what-if` Validierung dokumentieren

---

## Offene Architektur-Entscheidungen

### Frage 1: AzAuto-Common-Runbook-FW – Merge oder Submodul?

**Option A: Merge** (empfohlen für diesen Use Case)
- Framework-Funktionen direkt in `Workoho.CloudAdmin/Public/` übernehmen
- Ein Repo, ein Modul, ein Deployment
- Kein symlink-Chaos mehr
- Nachteil: Framework kann nicht mehr unabhängig versioniert/genutzt werden

**Option B: Eigenes Framework-Modul** (wenn Framework auch in anderen Projekten genutzt wird)
- `Workoho.AzAutoCommon` als separates Modul publizieren
- `Workoho.CloudAdmin` nimmt `Workoho.AzAutoCommon` als `RequiredModules`
- Beide ZIPs müssen ins Bicep-Deployment

### Frage 2: Graph API Permissions in Bicep

Graph API App Role Assignments können nicht nativ via Bicep/ARM gesetzt werden. Optionen:
1. `Microsoft.Resources/deploymentScripts` mit PowerShell 7 (empfohlen)
2. Manuelle Dokumentation, was ein Operator per Portal/CLI setzen muss
3. Terraform statt Bicep (hat Graph-Provider)

### Frage 3: Modul-Versionierung

- Semantisches Versioning: `2.x.y` (Bruch mit alter Architektur)
- Bicep-Parameter `moduleVersion` ermöglicht deployen einer bestimmten Version
- Git-Tags für Releases

---

## Nicht in Scope dieses Plans

- Migration von Windows PowerShell 5.1 Automation Accounts (die bestehende Umgebung läuft weiter bis zum Cutover)
- Tenant-Migration oder Entra-Konfigurationsänderungen
- UI/API für das Tiering-Modell
- Multi-Tenant-Unterstützung

---

## Erforderliche Bicep-Ressourcentypen (Referenz)

| Ressource | Bicep-Typ | API-Version |
|---|---|---|
| Automation Account | `Microsoft.Automation/automationAccounts` | `2023-11-01` |
| Runtime Environment | `Microsoft.Automation/automationAccounts/runtimeEnvironments` | `2023-11-01` |
| Module Package | `Microsoft.Automation/automationAccounts/runtimeEnvironments/packages` | `2023-11-01` |
| Runbook | `Microsoft.Automation/automationAccounts/runbooks` | `2023-11-01` |
| Automation Variable | `Microsoft.Automation/automationAccounts/variables` | `2023-11-01` |
| Schedule | `Microsoft.Automation/automationAccounts/schedules` | `2023-11-01` |
| Job Schedule | `Microsoft.Automation/automationAccounts/jobSchedules` | `2023-11-01` |
| Role Assignment | `Microsoft.Authorization/roleAssignments` | `2022-04-01` |
| Deployment Script | `Microsoft.Resources/deploymentScripts` | `2023-08-01` |
| Storage Account (temp) | `Microsoft.Storage/storageAccounts` | `2023-04-01` |

---

*Dokument-Status: Entwurf – bereit für Review und Umsetzungsentscheidung*
