#!/usr/bin/env bash
# Fetch the Mahimahi cellular traces used by the lte-driving profiles and
# check them against pinned SHA-256 sums. The trace files are NOT committed:
# they come from the Mahimahi repository, which is GPL-3.0 (see README.md).
set -euo pipefail
cd "$(dirname "$0")"
base=https://raw.githubusercontent.com/ravinet/mahimahi/f1346c38c415abfc98626dd82450f49a57033603/traces
while read -r sum name; do
  [ -f "$name" ] || curl -sSfL -o "$name" "$base/$name"
  echo "$sum  $name" | sha256sum -c --quiet -
done <<'EOF'
d58a640b9bccd131a421bff6eaf727aba324d9258b35009655bbf68e087b9b29 ATT-LTE-driving.up
73c58f41bf7a3f0fac82810ca61307521be1cf6b77a0e98093fd340bddfd161f ATT-LTE-driving.down
556620f1c11a61c7766678b08325ef4fc8d1bd774fbc98fb96854ae3d3795b61 TMobile-LTE-driving.up
d48ff134fc29c36cc3c3dee203464246bd698f0faede42534a27b0cbe3057055 TMobile-LTE-driving.down
669840f626966d7490a27629d4227eb2a866d40f104a6217c53b3f4b5a207d1f Verizon-LTE-driving.up
79f1860b7b195496d7d388d090edb3eaa9cecbbdfb489bf4a5a73d95d8c2e7ce Verizon-LTE-driving.down
6055d60d234030035f59475dc1d39d99e7c2817b9fa5d485f1f0710b1aae2075 Verizon-EVDO-driving.up
60c9cd7b5d8be7d89d3807052a043f54787958f04cfd4c6c16fcdac6e2c3b9da Verizon-EVDO-driving.down
EOF
echo "traces OK"
