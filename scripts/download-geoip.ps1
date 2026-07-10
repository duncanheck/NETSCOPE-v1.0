# Download the GeoLite2 City + ASN databases for NETSCOPE's A4 enrichment (Windows).
#
# The GeoLite2 databases are MaxMind's and their license forbids redistribution,
# so NETSCOPE does NOT bundle them — you fetch them with your own free license key.
#
#   1. Create a free MaxMind account: https://www.maxmind.com/en/geolite2/signup
#   2. Generate a license key in your account.
#   3. Run:  $env:MAXMIND_LICENSE_KEY="xxxxx"; .\scripts\download-geoip.ps1
#
# Files land in .\geoip (where the agent looks by default; override with
# NETSCOPE_GEOIP_DIR). The agent enables geo/ASN only if both files are present.
$ErrorActionPreference = "Stop"

if (-not $env:MAXMIND_LICENSE_KEY) {
  throw "Set MAXMIND_LICENSE_KEY (https://www.maxmind.com/en/accounts/current/license-key)"
}
$dest = if ($env:NETSCOPE_GEOIP_DIR) { $env:NETSCOPE_GEOIP_DIR } else { "geoip" }
New-Item -ItemType Directory -Force -Path $dest | Out-Null

function Fetch($edition) {
  Write-Host "-> $edition"
  $base = "https://download.maxmind.com/app/geoip_download"
  $url = "$base`?edition_id=$edition&license_key=$($env:MAXMIND_LICENSE_KEY)&suffix=tar.gz"
  $tmp = New-Item -ItemType Directory -Path ([System.IO.Path]::GetTempPath()) -Name ([System.Guid]::NewGuid())
  $tar = Join-Path $tmp "db.tar.gz"
  Invoke-WebRequest -Uri $url -OutFile $tar
  tar -xzf $tar -C $tmp
  $mmdb = Get-ChildItem -Path $tmp -Recurse -Filter *.mmdb | Select-Object -First 1
  Copy-Item $mmdb.FullName (Join-Path $dest "$edition.mmdb")
  Remove-Item -Recurse -Force $tmp
}

Fetch "GeoLite2-City"
Fetch "GeoLite2-ASN"

Write-Host "OK GeoLite2 databases in $dest\ - restart the agent to enable geo/ASN."
