#!/bin/bash
# Title: ECHOFIELD - HackRF Passive Radar Console
# Author: sinXne0
# Description: Turns the Pager into a passive-radar console. With two coherent HackRF channels it computes a range/Doppler map from an existing FM broadcast; simulation and recorded-IQ modes are included.
# Version: 0.1.0
# Category: user/reconnaissance
# Firmware: 2.0.0-stable or newer
# Requires: python3-light, libpagerctl.so (bundled)
# Optional: HackRF tools or ECHOFIELD_CAPTURE helper, two synchronized HackRFs
#
# Authorized testing and lawful spectrum use only. Passive receive mode is
# safe; transmit/capture modes require licensed hardware and permissions.
#
# Modes (ECHOFIELD_MODE):
#   sim     synthetic contacts, no hardware (default)
#   file    process two recorded IQ files
#   hackrf  capture two coherent HackRF channels
#
# LED States
#   Cyan     engine starting / idle
#   Amber    capture running
#   Green    contacts detected
#   Red      capture error
#   Off      stopped
#
# Loot
#   /root/loot/echofield/contacts.jsonl

# === PAYLOAD SDK STUBS ===
SUCCESS(){ echo "[+] $*"; }
FAIL(){ echo "[-] $*"; }
INFO(){ echo "[*] $*"; }
LED CLEANUP
LED ALL OFF
# === END SDK STUBS ===

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)"
[ -n "$SCRIPT_DIR" ] || SCRIPT_DIR="/root/payloads/user/reconnaissance/echofield"
export SCRIPT_DIR

PAYLOAD_DIR="${ECHOFIELD_DIR:-$SCRIPT_DIR}"
export PAYLOAD_DIR

STATE="${ECHOFIELD_STATE:-/tmp/echofield_state.json}"
CMD="${ECHOFIELD_CMD:-/tmp/echofield_cmd.jsonl}"
LOOT="${ECHOFIELD_LOOT:-/root/loot/echofield}"
export STATE CMD LOOT

LOG="${ECHOFIELD_LOG:-$LOOT/echofield.log}"
mkdir -p "$LOOT" /tmp
: > "$CMD"
rm -f "$STATE"

log(){ printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >> "$LOG" 2>/dev/null || true; }
die(){ FAIL "$*"; log "FAIL $*"; LED R 255 0 0; exit 1; }

if [ ! -f "$PAYLOAD_DIR/echofield.py" ]; then
  die "echofield.py not found in $PAYLOAD_DIR"
fi

PYTHON="$(command -v python3 || true)"
[ -n "$PYTHON" ] || die "python3 not installed"

if ! "$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3,6) else 1)' 2>/dev/null; then
  die "python3 >= 3.6 required"
fi

MODE="${ECHOFIELD_MODE:-sim}"
export ECHOFIELD_MODE="$MODE"
INFO "ECHOFIELD starting in $MODE mode"
log "start mode=$MODE dir=$PAYLOAD_DIR"

# Stop the stock UI so both processes do not drive the framebuffer.
if command -v pineapplepager >/dev/null 2>&1; then
  /etc/init.d/pineapplepager stop >/dev/null 2>&1 || true
  killall pineapplepager >/dev/null 2>&1 || true
fi

cleanup(){
  trap - INT TERM EXIT
  INFO "stopping ECHOFIELD"
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

LED C 0 180 255

"$PYTHON" "$PAYLOAD_DIR/echofield.py" engine >>"$LOG" 2>&1 &
ENGINE_PID=$!
sleep 0.4
kill -0 "$ENGINE_PID" 2>/dev/null || die "engine failed; see $LOG"

"$PYTHON" "$PAYLOAD_DIR/ef/ui.py" >>"$LOG" 2>&1 &
UI_PID=$!
sleep 0.4
kill -0 "$UI_PID" 2>/dev/null || die "UI failed; see $LOG"

LED C 0 180 255
SUCCESS "ECHOFIELD running - B exits, A starts/stops capture"

while true; do
  if ! kill -0 "$ENGINE_PID" 2>/dev/null; then
    die "engine exited unexpectedly; see $LOG"
  fi
  if ! kill -0 "$UI_PID" 2>/dev/null; then
    log "UI exited; engine stopped for safety"
    break
  fi
  if [ -f "$STATE" ]; then
    if grep -q '"phase":"off"' "$STATE" 2>/dev/null; then
      break
    fi
    if grep -q '"running":true' "$STATE" 2>/dev/null; then
      LED 255 176 32 2>/dev/null || true
    fi
  fi
  sleep 0.5
done

cleanup
