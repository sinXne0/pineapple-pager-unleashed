# UNLEASHED Installer

A Pager payload that pulls a payload from the
[pineapple-pager-unleashed](https://github.com/sinXne0/pineapple-pager-unleashed)
repo by its **pull-request number**.

## What it does

1. Asks for a PR number.
2. Fetches that PR's changed files via the GitHub API.
3. Downloads every `payloads/` file into the correct category directory
   (`/root/payloads/<category>/<name>/`, or the SD card if present).
4. Makes `payload.sh` executable, ready to launch.

## Requirements

- Internet access from the Pager.
- `curl` and `jq` (both standard on current firmware).

## Usage

Run **UNLEASHED Installer** from **Payloads → User Payloads**, enter the PR
number of the payload you want, confirm, and launch it from its category.

Authorized testing only — this downloads and runs third-party community code.
