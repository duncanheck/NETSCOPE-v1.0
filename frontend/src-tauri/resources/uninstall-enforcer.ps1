# NETSCOPE Warden — Windows enforcer service uninstaller.
#
# Stops and removes the service, deletes any remaining "NETSCOPE Warden" firewall
# rules (the service clears them on stop; this is belt and braces), and removes
# the installed binary. Run from an ELEVATED PowerShell.

$ErrorActionPreference = "Stop"
$ServiceName = "netscope-enforcer"
$InstallDir = Join-Path $env:ProgramFiles "NETSCOPE"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This uninstaller must run in an elevated PowerShell (Run as administrator)."
}

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne "Stopped") { Stop-Service $ServiceName -Force }
    sc.exe delete $ServiceName | Out-Null
    Write-Host "Service '$ServiceName' removed."
} else {
    Write-Host "Service '$ServiceName' not installed."
}

# Remove any leftover rules in our namespaced group.
$rules = @(Get-NetFirewallRule -Group "NETSCOPE Warden" -ErrorAction SilentlyContinue)
if ($rules.Count -gt 0) {
    $rules | Remove-NetFirewallRule
    Write-Host "Removed $($rules.Count) leftover firewall rule(s) in group 'NETSCOPE Warden'."
}

$exe = Join-Path $InstallDir "netscope-enforcer.exe"
if (Test-Path $exe) {
    Remove-Item -Force $exe
    Write-Host "Removed $exe."
}
Write-Host "Done. (The audit log at %ProgramData%\netscope\enforcer.log is kept.)"
