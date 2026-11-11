# UNLEASHED Installer

A Pager payload that turns the device into its own package manager for the
[pineapple-pager-unleashed](https://github.com/sinXne0/pineapple-pager-unleashed)
repo — the community home for payloads Hak5 won't merge.

## What it does

1. Fetches the repo's `index.json`.
2. Lists every payload in a picker.
3. Downloads the selected payload's files into the correct category directory
   (`/root/payloads/<category>/<name>/`, or the SD card if present).
4. Makes `payload.sh` executable, ready to launch.

## Requirements

- Internet access from the Pager.
- `curl` and `jq` (both standard on current firmware).

## Usage

Run **UNLEASHED Installer** from **Payloads → User Payloads**, pick a payload,
confirm, and launch it from its category.

Authorized testing only — this downloads and runs third-party community code.
