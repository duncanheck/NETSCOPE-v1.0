#!/usr/bin/env bash
# Download free threat-intelligence feeds for NETSCOPE's E2 reputation blocking.
#
# Like the GeoLite2 databases, NETSCOPE ships the *downloader*, not the data: the
# feeds have their own licenses and update constantly, so you fetch fresh copies
# rather than committing a stale snapshot. Everything here is free and public.
#
#   ./scripts/download-threatfeeds.sh
#
# Files land in ./threatfeeds (where the agent looks by default; override with
# NETSCOPE_THREAT_DIR). The agent loads whatever is present at startup and turns
# the "known-bad lists" toggle on once at least one feed is loaded. Re-run any
# time to refresh; cron/Task Scheduler it for always-fresh intel.
#
# Feeds (all free):
#   - StevenBlack unified hosts  — ads + malware domains   (MIT)
#   - abuse.ch URLhaus hostfile  — active malware domains  (CC0)
#   - abuse.ch Feodo IP blocklist — botnet C2 IPs           (CC0)
#   - FireHOL level 1            — known-bad IPs/CIDRs      (public)
set -euo pipefail

DEST="${NETSCOPE_THREAT_DIR:-threatfeeds}"
mkdir -p "$DEST"

fetch() {
  local name="$1" url="$2"
  echo "→ $name"
  # -f: fail on HTTP errors; --retry: ride out transient blips. A feed that
  # fails to download is skipped, not fatal — partial intel still helps.
  if ! curl -fSL --retry 3 --retry-delay 2 "$url" -o "$DEST/$name"; then
    echo "  ! skipped $name (download failed)"
    rm -f "$DEST/$name"
  fi
}

# Domain feeds (.hosts = "0.0.0.0 domain" lines; .domains = one per line).
fetch stevenblack.hosts   "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
fetch urlhaus.hosts       "https://urlhaus.abuse.ch/downloads/hostfile/"

# IP feeds (.ips = one IP or CIDR per line).
fetch feodo.ips           "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
fetch firehol_level1.ips  "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"

count=$(find "$DEST" -maxdepth 1 -type f | wc -l | tr -d ' ')
echo "✓ $count threat feed(s) in $DEST/ — restart the agent to enable reputation blocking."
