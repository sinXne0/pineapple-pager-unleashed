#!/bin/bash
# Title: ELRSJACK - ELRS 900M Link Credential Recovery
# Author: sinXne0
# Description: Uses the Glytch Mesh Mod's SX1262 LoRa radio to capture one ELRS 900M sync packet, recover the FHSS seed / binding phrase from observed hop timing, and run a link probe against an authorized bench receiver. Link-layer only: no flight/vehicle control packets are generated.
# Version: 1.0.0
# Category: user/general
# Firmware: 2.0.0-stable or newer
# Requires: python3-light, Glytch Mesh Mod (SX1262 on ch341 SPI), meshtasticd installed
# Optional: none. No cross-compilation, no third-party Python packages.
#
# AUTHORIZED TESTING ONLY. Use on an ELRS link and bench receiver you own or
# have explicit written permission to test. Never point this at a live craft.
#
# HARD CONSTRAINTS (state these before use):
#   - Hardware: Glytch Mesh Mod SX1262 (ch341 SPI, VID 1A86:5512). meshtasticd
#     is STOPPED for the duration and restarted on exit.
#   - Frequency: sub-GHz ELRS only (433/868/915 MHz domains). 2.4 GHz ELRS
#     uses an SX1280 and is NOT supported.
#   - The installed meshtasticd 2.7.26 must be stopped first; while it runs
#     the SPI device is owned by Meshtastic and ELRSJACK reports NO RADIO.
#   - ELRS 900M officially targets SX1276; the SX1262 sync-word register is
#     not standardised. The operator cycles candidate sync words with B in
#     the SCAN screen; every packet is validated by the ELRS OTA CRC -- no
#     packet is trusted on word match alone. If none validate, status stays
#     at 0 and nothing is claimed.
#   - UID[0:2] are never transmitted and are always reported as 00 00.
#   - FHSS seed recovery is normally ambiguous between two values differing
#     in UID[2] bit 7 (ELRS LCG discards the top seed bit). The wordlist
#     cracker disambiguates by exact MD5 tail; otherwise it stays AMBIGUOUS.
#   - No live bench receiver or mesh was available during development.
#     Everything is validated with hardware-free mocks only.
#
# LED States
#   Cyan     engine starting / idle
#   Amber    capture or brute-force running
#   Green    phrase confirmed from an exact MD5 match
#   Red      capability check failed / error
#   Off      stopped
#
# Loot
#   /root/loot/elrsjack/elrsjack.log   engine/UI log
#   /root/loot/elrsjack/capture.json   capture snapshot
#   /root/loot/elrsjack/result.json    UID, phrase and probe results

# === PAYLOAD SDK STUBS ===
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)"
if ! command -v LOG          >/dev/null 2>&1; then LOG()          { echo "$*"; }; fi
if ! command -v LED          >/dev/null 2>&1; then LED()          { :; }; fi
if ! command -v ERROR_DIALOG >/dev/null 2>&1; then ERROR_DIALOG() { echo "ERROR: $*"; }; fi
if ! command -v CONFIRMATION_DIALOG >/dev/null 2>&1; then CONFIRMATION_DIALOG() { echo "${ELRSJACK_CONFIRM:-true}"; }; fi

# === SELF-LOCATE ===
PAYLOAD_DIR=""
for candidate in "$SCRIPT_DIR" \
                 "${ELRSJACK_PAYLOAD_DIR:-}" \
                 /root/payloads/user/*/elrsjack \
                 /mmc/root/payloads/user/*/elrsjack; do
    [ -n "$candidate" ] || continue
    if [ -f "$candidate/elrsjack.py" ]; then
        PAYLOAD_DIR="$candidate"
        break
    fi
done

if [ -z "$PAYLOAD_DIR" ]; then
    LED RED 2>/dev/null
    LOG "red" "elrsjack.py not found next to payload.sh"
    ERROR_DIALOG "ELRSJACK files missing.\nRedeploy the payload folder."
    exit 1
fi

export PYTHONPATH="$PAYLOAD_DIR:$PAYLOAD_DIR/lib:${PYTHONPATH}"

STATE="${ELRSJACK_STATE:-/tmp/elrsjack_state.json}"
CMD="${ELRSJACK_CMD:-/tmp/elrsjack_cmd.jsonl}"
LOOT="${ELRSJACK_LOOT:-/root/loot/elrsjack}"
export STATE CMD LOOT

LOG_FILE="$LOOT/elrsjack.log"
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

# Capability check: stdlib protocol primitives must work before we touch radio.
"$PYTHON" "$PAYLOAD_DIR/elrsjack.py" capcheck >>"$LOG_FILE" 2>&1 || die "capability check failed; see $LOG_FILE"

# Authorization gate -- explicit acceptance before any radio work.
CONFIRM="$(CONFIRMATION_DIALOG "ELRSJACK uses the Mesh Mod SX1262 to recover an ELRS 900M link credential.\n\nAuthorized bench testing ONLY. Never point this at a live craft or vehicle.\n\nContinue?" 2>/dev/null || true)"
case "$CONFIRM" in
  true|TRUE|yes|YES|A|a) ;;
  *) INFO "Authorization declined. Exiting."; exit 0 ;;
esac

INFO "ELRSJACK starting"
log "start dir=$PAYLOAD_DIR"

# Stop the stock UI so both processes do not fight over the framebuffer.
if command -v pineapplepager >/dev/null 2>&1; then
  /etc/init.d/pineapplepager stop >/dev/null 2>&1 || true
  killall pineapplepager >/dev/null 2>&1 || true
fi

# Meshtastic must release the SX1262 SPI device.  Remember whether we stopped
# it so we can restore the operator's previous state on exit.
MESHTASTIC_WAS_RUNNING=0
if [ -x /etc/init.d/meshtasticd ]; then
  /etc/init.d/meshtasticd status >/dev/null 2>&1 && MESHTASTIC_WAS_RUNNING=1
  /etc/init.d/meshtasticd stop >/dev/null 2>&1 || true
  log "meshtasticd stopped (was_running=$MESHTASTIC_WAS_RUNNING)"
else
  log "meshtasticd init script not found; continuing (radio may be busy)"
fi
sleep 0.5

cleanup(){
  trap - INT TERM EXIT
  INFO "stopping ELRSJACK"
  log "stop"
  [ -n "$ENGINE_PID" ] && kill "$ENGINE_PID" >/dev/null 2>&1 || true
  [ -n "$UI_PID" ] && kill "$UI_PID" >/dev/null 2>&1 || true
  wait "$ENGINE_PID" >/dev/null 2>&1 || true
  wait "$UI_PID" >/dev/null 2>&1 || true
  rm -f "$STATE" "$CMD"
  if [ "$MESHTASTIC_WAS_RUNNING" -eq 1 ] && [ -x /etc/init.d/meshtasticd ]; then
    /etc/init.d/meshtasticd start >/dev/null 2>&1 || true
    log "meshtasticd restored"
  fi
  LED ALL OFF
  exit 0
}
trap cleanup INT TERM EXIT

ENGINE_PID=""
UI_PID=""
LED C 0 180 255

"$PYTHON" "$PAYLOAD_DIR/elrsjack.py" engine >>"$LOG_FILE" 2>&1 &
ENGINE_PID=$!
sleep 0.4
kill -0 "$ENGINE_PID" 2>/dev/null || die "engine failed; see $LOG_FILE"

"$PYTHON" "$PAYLOAD_DIR/elrs/ui.py" >>"$LOG_FILE" 2>&1 &
UI_PID=$!
sleep 0.4
kill -0 "$UI_PID" 2>/dev/null || die "UI failed; see $LOG_FILE"

SUCCESS "ELRSJACK running. Authorize in the UI, then SCAN 10s, TRACK, RECOVER, CRACK."
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
    if grep -q '"phrase":{"value":' "$STATE" 2>/dev/null && \
       grep -q '"confirmed":true' "$STATE" 2>/dev/null; then
      LED 0 235 130 2>/dev/null || true
    elif grep -q '"phase":"capture"' "$STATE" 2>/dev/null || \
         grep -q '"phase":"track"' "$STATE" 2>/dev/null || \
         grep -q '"phase":"crack"' "$STATE" 2>/dev/null; then
      LED 255 176 32 2>/dev/null || true
    fi
  fi
  sleep 0.5
done

cleanup
