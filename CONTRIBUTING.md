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

## index.json

The installer reads `index.json` at the repo root. Add an entry for your
payload so it shows up in the picker:

```json
{
  "name": "mypayload",
  "title": "My Payload — what it does",
  "category": "user/interception",
  "desc": "One-line description shown in the installer.",
  "files": ["payload.sh", "engine.py", "README.md"]
}
```

- `name` — directory name (unique).
- `title` — display title (unique, shown in the picker).
- `category` — one of the categories above.
- `desc` — one-line summary.
- `files` — every file the payload needs to run, relative to the payload
  directory. Include nested paths (`lib/pagerctl.so`, `web/index.html`). The
  installer downloads exactly these.

Keep `index.json` sorted alphabetically by `name`.

## Testing

- `bash -n payload.sh` passes.
- State what firmware and what network conditions you tested on.
- Note any dependencies (`python3-light`, `aircrack-ng`, `hostapd`, ...).

## Legal

By opening a pull request you confirm the payload is for authorized testing
and you have the right to contribute it.
