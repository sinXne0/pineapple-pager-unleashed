#!/bin/bash
# Title: UNLEASHED - Payload Installer
# Description: Pull a payload from the pineapple-pager-unleashed community repo
#              by its pull-request number. No laptop required.
# Author: sinXne0
# Version: 2.0
# Category: user/general
# Firmware: 2.0.0-stable or newer

REPO="sinXne0/pineapple-pager-unleashed"
API="https://api.github.com/repos/$REPO"
RAW="https://raw.githubusercontent.com/$REPO"

# --- DuckyScript stubs (dev / non-Pager) -----------------------------------
command -v LOG >/dev/null 2>&1                || LOG() { echo "${2:-}"; }
command -v ALERT >/dev/null 2>&1              || ALERT() { echo "ALERT: $*"; }
command -v ERROR_DIALOG >/dev/null 2>&1       || ERROR_DIALOG() { echo "ERROR: $*"; }
command -v TEXT_PICKER >/dev/null 2>&1        || TEXT_PICKER() { echo "${2:-}"; }
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
LOG "Install a payload by its PR number in"
LOG "github.com/$REPO"

# --- show the registry (durable number -> payload mapping) -----------------
REG=$(curl -fsSL "$RAW/main/index.json" 2>/dev/null)
if [ -n "$REG" ]; then
    LOG ""
    LOG cyan "Payloads (number - what it is):"
    echo "$REG" | jq -r '.payloads[] | "  #\(.pr)  \(.title)"' | while IFS= read -r line; do
        LOG "$line"
    done
    LOG ""
else
    LOG yellow "  (could not load the registry - enter a number manually)"
fi

# --- ask for the PR number -------------------------------------------------
PR=$(TEXT_PICKER "Pull request number" "")
[ -z "$PR" ] && exit 0
case "$PR" in
    ''|*[!0-9]*) ERROR_DIALOG "Enter a numeric PR number."; exit 1 ;;
esac

# --- fetch PR info (head commit) + changed files ---------------------------
LED BLUE 2>/dev/null
LOG cyan "Fetching PR #$PR ..."

PR_INFO=$(curl -fsSL "$API/pulls/$PR" 2>/dev/null)
if [ -z "$PR_INFO" ]; then
    LED RED 2>/dev/null
    ERROR_DIALOG "Could not fetch PR #$PR.\n\nCheck the number and internet access."
    exit 1
fi
HEAD_SHA=$(echo "$PR_INFO" | jq -r '.head.sha // empty')
TITLE=$(echo "$PR_INFO" | jq -r '.title // ("PR #" + $pr)' --arg pr "$PR")
if [ -z "$HEAD_SHA" ]; then
    LED RED 2>/dev/null
    ERROR_DIALOG "PR #$PR not found."
    exit 1
fi

FILES=$(curl -fsSL "$API/pulls/$PR/files" 2>/dev/null)
if [ -z "$FILES" ]; then
    LED RED 2>/dev/null
    ERROR_DIALOG "Could not fetch PR #$PR files."
    exit 1
fi

# Only files under payloads/, ignoring removals.
LIST=$(echo "$FILES" | jq -c '[.[] | select(.filename | startswith("payloads/")) | select(.status != "removed")]')
COUNT=$(echo "$LIST" | jq 'length')
if [ "$COUNT" -eq 0 ]; then
    ALERT "PR #$PR has no payload files.\n\n$TITLE"
    exit 0
fi

LOG cyan "PR #$PR: $TITLE"
LOG "  $COUNT file(s) to install"

resp=$(CONFIRMATION_DIALOG "Install PR #$PR?\n\n$TITLE\n\nThis downloads and runs community code.")
confirmed "$resp" || { LOG "Cancelled."; exit 0; }

# --- download each file ----------------------------------------------------
LED BLUE 2>/dev/null
FAIL=0
while IFS= read -r filename; do
    [ -z "$filename" ] && continue
    rel="${filename#payloads/}"
    dest="$PAYLOAD_ROOT/$rel"
    mkdir -p "$(dirname "$dest")"
    LOG cyan "  $rel ..."
    if ! curl -fsSL "$RAW/$HEAD_SHA/$filename" -o "$dest"; then
        LOG red "  FAILED: $rel"
        FAIL=1
    fi
done < <(echo "$LIST" | jq -r '.[].filename')

# --- make payload.sh files executable --------------------------------------
while IFS= read -r filename; do
    case "$filename" in
        */payload.sh) chmod +x "$PAYLOAD_ROOT/${filename#payloads/}" 2>/dev/null ;;
    esac
done < <(echo "$LIST" | jq -r '.[].filename')

NAMES=$(echo "$LIST" | jq -r '[.[].filename | select(endswith("/payload.sh")) | split("/") | .[-2]] | unique | join(", ")')

if [ "$FAIL" -eq 0 ]; then
    LED GREEN 2>/dev/null
    ALERT "Installed: $NAMES\n\nfrom PR #$PR\n\nRun it from the payload menu."
else
    LED AMBER 2>/dev/null
    ALERT "Installed with errors.\n\nPR #$PR"
fi
exit 0
