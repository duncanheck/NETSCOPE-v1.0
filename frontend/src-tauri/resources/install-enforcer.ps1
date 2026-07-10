# NETSCOPE Warden — Windows enforcer service installer (E4).
#
# Installs `netscope-enforcer.exe` as a Windows service (LocalSystem — it edits
# Windows Firewall rules, which needs elevation) and authorizes ONE desktop user
# to drive it over the named pipe. The service:
#
#   - listens on \\.\pipe\netscope-enforcer (the well-known name the NETSCOPE
#     agent auto-detects — installing this service is the whole opt-in),
#   - authenticates every connection by the client process token's user SID,
#   - only ever edits its own firewall group ("NETSCOPE Warden"),
#   - enforces the never-block floor itself (loopback/LAN/tailnet can't be cut),
#   - audits every change to %ProgramData%\netscope\enforcer.log,
#   - clears its rules on service stop (fail-open: blocks live only while it runs).
#
# Run from an ELEVATED PowerShell:
#   .\install-enforcer.ps1                         # authorizes the current user
#   .\install-enforcer.ps1 -User "MACHINE\alice"   # authorizes another account
#   .\install-enforcer.ps1 -ExePath "C:\path\to\netscope-enforcer.exe"
#
# Remove with .\uninstall-enforcer.ps1.

[CmdletBinding()]
param(
    # The account allowed to drive the enforcer (the user who runs NETSCOPE).
    # Defaults to the current user (under UAC elevation that is still you).
    [string]$User = "",
    # Path to netscope-enforcer.exe. Defaults to one sitting next to this script,
    # then to the NETSCOPE desktop-app install directory.
    [string]$ExePath = ""
)

$ErrorActionPreference = "Stop"
$ServiceName = "netscope-enforcer"
$InstallDir = Join-Path $env:ProgramFiles "NETSCOPE"
$LogPath = Join-Path $env:ProgramData "netscope\enforcer.log"

# --- Elevation check ---------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This installer must run in an elevated PowerShell (Run as administrator)."
}

# --- Resolve the binary ------------------------------------------------------
if (-not $ExePath) {
    $candidates = @(
        (Join-Path $PSScriptRoot "netscope-enforcer.exe"),
        # The desktop bundle puts this script in <app>\resources\, exe one level up.
        (Join-Path (Split-Path $PSScriptRoot -Parent) "netscope-enforcer.exe"),
        (Join-Path $env:LOCALAPPDATA "NETSCOPE\netscope-enforcer.exe"),
        (Join-Path $InstallDir "netscope-enforcer.exe")
    )
    $ExePath = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $ExePath) {
        Write-Error "netscope-enforcer.exe not found next to this script; pass -ExePath."
    }
}

# --- Resolve the authorized user's SID ---------------------------------------
if (-not $User) {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $who = [Security.Principal.WindowsIdentity]::GetCurrent().Name
} else {
    $account = New-Object Security.Principal.NTAccount($User)
    $sid = $account.Translate([Security.Principal.SecurityIdentifier]).Value
    $who = $User
}
Write-Host "Authorizing $who ($sid) to drive the enforcer."

# --- Install the binary under Program Files (not a user-writable path) --------
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$target = Join-Path $InstallDir "netscope-enforcer.exe"
Copy-Item -Force $ExePath $target
New-Item -ItemType Directory -Force -Path (Split-Path $LogPath) | Out-Null

# --- (Re)create the service ---------------------------------------------------
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Service exists - stopping and reinstalling."
    if ($existing.Status -ne "Stopped") { Stop-Service $ServiceName -Force }
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

# ImagePath arguments reach the process argv, so config rides the binPath.
$binPath = "`"$target`" --service --allow-sid $sid --log `"$LogPath`""
sc.exe create $ServiceName binPath= $binPath start= auto obj= LocalSystem DisplayName= "NETSCOPE Warden enforcer" | Out-Null
sc.exe description $ServiceName "Applies NETSCOPE Warden block rules to Windows Firewall (namespaced group 'NETSCOPE Warden'). Authenticated local named pipe; never-block floor enforced service-side." | Out-Null

Start-Service $ServiceName
$svc = Get-Service $ServiceName
Write-Host ""
Write-Host "Service '$ServiceName' is $($svc.Status)."
Write-Host "Pipe:      \\.\pipe\netscope-enforcer"
Write-Host "Audit log: $LogPath"
Write-Host ""
Write-Host "NETSCOPE will detect the enforcer automatically - open the block panel and"
Write-Host "the enforcement section lights up (restart NETSCOPE if it was running)."
