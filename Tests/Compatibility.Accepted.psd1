# Findings of Test-Compatibility.ps1 that do not apply to Windows PowerShell 5.1, each with its reason.
@{
    Accepted     = @()
    # The framework runbooks, which Update-AzAutoFWProject.ps1 links into Runbooks/. The framework checks them itself.
    ExcludeFiles = @('Common_*')
}
