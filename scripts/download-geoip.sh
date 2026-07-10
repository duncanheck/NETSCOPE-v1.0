#!/usr/bin/env bash
# Download the GeoLite2 City + ASN databases for NETSCOPE's A4 enrichment.
#
# The GeoLite2 databases are MaxMind's and their license forbids redistribution,
# so NETSCOPE does NOT bundle them — you fetch them with your own free license key.
#
#   1. Create a free MaxMind account: https://www.maxmind.com/en/geolite2/signup
#   2. Generate a license key in your account.
#   3. Run:  MAXMIND_LICENSE_KEY=xxxxx ./scripts/download-geoip.sh
#
# Files land in ./geoip (where the agent looks by default; override with
# NETSCOPE_GEOIP_DIR). The agent enables geo/ASN only if both files are present.
set -euo pipefail

: "${MAXMIND_LICENSE_KEY:?Set MAXMIND_LICENSE_KEY (https://www.maxmind.com/en/accounts/current/license-key)}"
DEST="${NETSCOPE_GEOIP_DIR:-geoip}"
mkdir -p "$DEST"

base="https://download.maxmind.com/app/geoip_download"
fetch() {
  local edition="$1"
  echo "→ $edition"
  local tmp
  tmp="$(mktemp -d)"
  curl -fSL "${base}?edition_id=${edition}&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz" \
    -o "$tmp/db.tar.gz"
  # The .mmdb lives in a dated subdirectory inside the tarball; extract just it.
  tar -xzf "$tmp/db.tar.gz" -C "$tmp"
  find "$tmp" -name '*.mmdb' -exec cp {} "$DEST/${edition}.mmdb" \;
  rm -rf "$tmp"
}

fetch GeoLite2-City
fetch GeoLite2-ASN

echo "✓ GeoLite2 databases in $DEST/ — restart the agent to enable geo/ASN."
