# Download free threat-intelligence feeds for NETSCOPE's E2 reputation blocking (Windows).
#
# Like the GeoLite2 databases, NETSCOPE ships the *downloader*, not the data: the
# feeds have their own licenses and update constantly, so you fetch fresh copies
# rather than committing a stale snapshot. Everything here is free and public.
#
#   .\scripts\download-threatfeeds.ps1
#
# Files land in .\threatfeeds (where the agent looks by default; override with
# NETSCOPE_THREAT_DIR). The agent loads whatever is present at startup and turns
# the "known-bad lists" toggle on once at least one feed is loaded. Re-run any
# time to refresh; schedule it for always-fresh intel.
#
# Feeds (all free):
#   - StevenBlack unified hosts  - ads + malware domains   (MIT)
#   - abuse.ch URLhaus hostfile  - active malware domains  (CC0)
#   - abuse.ch Feodo IP blocklist - botnet C2 IPs           (CC0)
#   - FireHOL level 1            - known-bad IPs/CIDRs      (public)
$ErrorActionPreference = "Stop"

$dest = if ($env:NETSCOPE_THREAT_DIR) { $env:NETSCOPE_THREAT_DIR } else { "threatfeeds" }
New-Item -ItemType Directory -Force -Path $dest | Out-Null

function Fetch($name, $url) {
  Write-Host "-> $name"
  $out = Join-Path $dest $name
  try {
    Invoke-WebRequest -Uri $url -OutFile $out -MaximumRetryCount 3 -RetryIntervalSec 2
  } catch {
    Write-Host "  ! skipped $name (download failed)"
    Remove-Item -Force -ErrorAction SilentlyContinue $out
  }
}

# Domain feeds (.hosts = "0.0.0.0 domain" lines; .domains = one per line).
Fetch "stevenblack.hosts"  "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
Fetch "urlhaus.hosts"      "https://urlhaus.abuse.ch/downloads/hostfile/"

# IP feeds (.ips = one IP or CIDR per line).
Fetch "feodo.ips"          "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
Fetch "firehol_level1.ips" "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"

$count = (Get-ChildItem -Path $dest -File).Count
Write-Host "OK $count threat feed(s) in $dest\ - restart the agent to enable reputation blocking."
