# Contributing

Thanks for wanting to add a payload. This repo exists because the official
Hak5 payload library won't take certain payloads — here, that's the point.

## Rules

- **Authorized testing only.** Payloads must be for security testing, research,
  or education on systems you are authorized to assess. No malware, no
  ransomware, no credential *theft* targeting third parties.
- **One payload per pull request.**
- **The payload must actually run** on the WiFi Pineapple Pager (firmware
  `2.0.0-stable` or newer is the baseline). State what you tested on.
- **Reversible where possible** — clean up services/interfaces/files on exit.

## Payload structure

Every payload lives at `payloads/<category>/<name>/` and must include a
`payload.sh` with a standard DuckyScript header:

```bash
#!/bin/bash
# Title: MYPAYLOAD - short description
# Description: longer description
# Author: yourname
# Version: 1.0
# Category: user/interception     # or recon/access_point, alerts/...
# Firmware: 2.0.0-stable or newer
```

Valid categories (matching the Pager's payload roots):

| Category | Path on Pager |
| --- | --- |
| `user/interception` | `/root/payloads/user/interception/<name>/` |
| `user/reconnaissance` | `/root/payloads/user/reconnaissance/<name>/` |
| `user/exfiltration` | `/root/payloads/user/exfiltration/<name>/` |
| `user/general` | `/root/payloads/user/general/<name>/` |
| `recon/access_point` | `/root/payloads/recon/access_point/<name>/` |
| `recon/client` | `/root/payloads/recon/client/<name>/` |
| `alerts/<type>` | `/root/payloads/alerts/<type>/<name>/` |

## How the installer finds your payload

The installer works by PR number. When a user enters your PR number, it
fetches that PR's changed files via the GitHub API and installs every file
under `payloads/`.

Every payload also has a permanent entry in **`index.json`** (the registry) at
the repo root. This is the durable number→payload mapping — it keeps working
after the PR is merged, so people always know which number installs which
payload. A GitHub Action updates `index.json` **automatically** when your PR
is merged, so you don't need to touch it.

Keep the payload directory self-contained: every file the payload needs to run
must be in that directory (including nested paths like `lib/pagerctl.so` or
`web/index.html`).

## Testing

- `bash -n payload.sh` passes.
- State what firmware and what network conditions you tested on.
- Note any dependencies (`python3-light`, `aircrack-ng`, `hostapd`, ...).

## Legal

By opening a pull request you confirm the payload is for authorized testing
and you have the right to contribute it.
