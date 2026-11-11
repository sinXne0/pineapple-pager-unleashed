#!/bin/bash
# Title: UNLEASHED - Payload Installer
# Description: Browse and install payloads from the pineapple-pager-unleashed
#              community repo (payloads Hak5 won't merge). Pulls the selected
#              payload straight onto the Pager - no laptop required.
# Author: sinXne0
# Version: 1.0
# Category: user/general
# Firmware: 2.0.0-stable or newer

REPO="sinXne0/pineapple-pager-unleashed"
BRANCH="main"
BASE="https://raw.githubusercontent.com/$REPO/$BRANCH"
INDEX_URL="$BASE/index.json"
CACHE="/tmp/unleashed_index.json"

# --- DuckyScript stubs (dev / non-Pager) -----------------------------------
command -v LOG >/dev/null 2>&1                || LOG() { echo "${2:-}"; }
command -v ALERT >/dev/null 2>&1              || ALERT() { echo "ALERT: $*"; }
command -v ERROR_DIALOG >/dev/null 2>&1       || ERROR_DIALOG() { echo "ERROR: $*"; }
command -v LIST_PICKER >/dev/null 2>&1        || LIST_PICKER() { echo "${2:-}"; }
command -v LED >/dev/null 2>&1                || LED() { :; }
command -v CONFIRMATION_DIALOG >/dev/null 2>&1 || CONFIRMATION_DIALOG() { echo "true"; }

confirmed() {
    [ "$1" = "$DUCKYSCRIPT_USER_CONFIRMED" ] || [ "$1" = "true" ]
}

# --- payload root (SD card preferred) --------------------------------------
PAYLOAD_ROOT="/root/payloads"
[ -d /mmc/root/payloads ] && PAYLOAD_ROOT="/mmc/root/payloads"

LED BLUE 2>/dev/null
LOG ""
LOG magenta "  U N L E A S H E D  -  payload installer"
LOG ""
LOG cyan "Fetching index from $REPO ..."

INDEX=$(curl -fsSL "$INDEX_URL" 2>/dev/null)
if [ -z "$INDEX" ]; then
    LED RED 2>/dev/null
    ERROR_DIALOG "Cannot reach $REPO\n\nCheck that the Pager has internet access, then retry."
    exit 1
fi
echo "$INDEX" > "$CACHE"

# --- build the picker label list -------------------------------------------
mapfile -t LABELS < <(echo "$INDEX" | jq -r '.payloads[] | (.title // .name)')
COUNT="${#LABELS[@]}"
if [ "$COUNT" -eq 0 ]; then
    ALERT "The repo has no payloads yet.\n\nContribute at github.com/$REPO"
    exit 0
fi

PICK=$(LIST_PICKER "UNLEASHED payloads ($COUNT)" "${LABELS[@]}")
[ -z "$PICK" ] && exit 0

# --- resolve the selection back to name/category/desc ----------------------
SELQ='.payloads[] | select((.title // .name) == $t)'
NAME=$(echo "$INDEX" | jq -r --arg t "$PICK" "$SELQ | .name")
CATEGORY=$(echo "$INDEX" | jq -r --arg t "$PICK" "$SELQ | .category")
DESC=$(echo "$INDEX" | jq -r --arg t "$PICK" "$SELQ | .desc")

if [ -z "$NAME" ] || [ -z "$CATEGORY" ]; then
    ALERT "Could not resolve the selection."
    exit 1
fi

DEST="$PAYLOAD_ROOT/$CATEGORY/$NAME"
[ -n "$DESC" ] && LOG "  $DESC"

resp=$(CONFIRMATION_DIALOG "Install \"$NAME\"?\n\n$DEST\n\nThis downloads and runs community code.")
confirmed "$resp" || { LOG "Cancelled."; exit 0; }

# --- download every file in the manifest -----------------------------------
LED BLUE 2>/dev/null
mkdir -p "$DEST"
FAIL=0
while IFS= read -r f; do
    [ -z "$f" ] && continue
    mkdir -p "$DEST/$(dirname "$f")"
    LOG cyan "  fetching $f ..."
    if ! curl -fsSL "$BASE/payloads/$CATEGORY/$NAME/$f" -o "$DEST/$f"; then
        LOG red "  FAILED: $f"
        FAIL=1
    fi
done < <(echo "$INDEX" | jq -r --arg t "$PICK" "$SELQ | .files[]")

chmod +x "$DEST/payload.sh" 2>/dev/null

if [ "$FAIL" -eq 0 ]; then
    LED GREEN 2>/dev/null
    ALERT "Installed: $NAME\n\n$DEST\n\nRun it from the payload menu."
else
    LED AMBER 2>/dev/null
    ALERT "Installed with errors: $NAME\n\n$DEST\n\nSome files failed to download."
fi
exit 0
