#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)

deploy() {
  local source=$1 destination=$2 mode=$3 encoded
  encoded=$(base64 -w0 "$source")
  "$ROOT/host/guest-exec.sh" /bin/sh -c \
    "umask 077; printf '%s' '$encoded' | base64 -d > '$destination.new'; chmod '$mode' '$destination.new'; mv '$destination.new' '$destination'"
}

deploy "$ROOT/bin/avbox-bootstrap.py" /usr/local/lib/avbox-bootstrap/avbox-bootstrap.py 0755
deploy "$ROOT/config/acquisition.yaml" /etc/avbox-bootstrap/acquisition.yaml 0444
"$ROOT/host/guest-exec.sh" /bin/sh -c \
  "install -m 0444 /etc/avbox-bootstrap/acquisition.yaml /srv/avbox-bootstrap/manifests/acquisition.yaml"
if [[ -f "$ROOT/reports/time-critical-status.md" ]]; then
  deploy "$ROOT/reports/time-critical-status.md" /srv/avbox-bootstrap/manifests/time-critical-status.md 0444
fi
if [[ -f "$ROOT/reports/preserve-before-m0.md" ]]; then
  deploy "$ROOT/reports/preserve-before-m0.md" /srv/avbox-bootstrap/manifests/preserve-before-m0.md 0444
fi
if [[ -f "$ROOT/reports/historical-linux-unix-deep-pass.md" ]]; then
  deploy "$ROOT/reports/historical-linux-unix-deep-pass.md" /srv/avbox-bootstrap/manifests/historical-linux-unix-deep-pass.md 0444
fi
if [[ -f "$ROOT/reports/dos-os2-deep-pass.md" ]]; then
  deploy "$ROOT/reports/dos-os2-deep-pass.md" /srv/avbox-bootstrap/manifests/dos-os2-deep-pass.md 0444
fi
if [[ -f "$ROOT/reports/old-windows-deep-pass.md" ]]; then
  deploy "$ROOT/reports/old-windows-deep-pass.md" /srv/avbox-bootstrap/manifests/old-windows-deep-pass.md 0444
fi
if [[ -f "$ROOT/config/old-windows-final-matrix.yaml" ]]; then
  deploy "$ROOT/config/old-windows-final-matrix.yaml" /srv/avbox-bootstrap/manifests/old-windows-final-matrix.yaml 0444
fi
if [[ -f "$ROOT/config/rab-future-acquisition.yaml" ]]; then
  deploy "$ROOT/config/rab-future-acquisition.yaml" /srv/avbox-bootstrap/manifests/rab-future-acquisition.yaml 0444
fi
