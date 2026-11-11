# Pineapple Pager — Unleashed

**Community payloads for the WiFi Pineapple Pager that don't fit Hak5's
official payload repo.**

Hak5's [official payload library](https://github.com/hak5/wifipineapplepager-payloads)
curates payloads that are safe, broadly supported, and fit their brand. This
repo is the flip side: a home for offensive, aggressive, or otherwise
**uncensored** payloads that Hak5 won't merge — and a place where anyone can
submit a pull request to add their own.

> **Authorized testing only.** Payloads here may deauthenticate clients,
> capture credentials, or disrupt networks. You are responsible for running
> them only against networks, devices, and accounts you own or have written
> permission to test, and for compliance with local law.

---

## The installer

The repo ships a payload that turns the Pager into its own package manager:
**UNLEASHED Installer** (`payloads/user/general/unleashed-installer/`).

It shows the numbered registry (`index.json`) so you always know which number
installs which payload, then you enter a **number** and it pulls that payload
straight onto the Pager — no laptop, no `scp`, no `git`.

### Install the installer (one time)

Copy the installer folder onto the Pager:

```sh
scp -r payloads/user/general/unleashed-installer \
  root@172.16.42.1:/root/payloads/user/general/
ssh root@172.16.42.1 'chmod +x /root/payloads/user/general/unleashed-installer/payload.sh'
```

Then run **UNLEASHED Installer** from **Payloads → User Payloads**. It lists
the numbered payloads, you enter the number of the one you want, confirm, and
it lands in the correct category directory, ready to launch.

---

## Submitting a payload

Anyone can add a payload with a pull request. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the full rules.

The short version:

1. Fork this repo and create a branch.
2. Add your payload under `payloads/<category>/<name>/`:
   ```text
   payloads/user/interception/mypayload/
     payload.sh          # required, executable, with a DuckyScript header
     ...                 # any supporting files
     README.md           # recommended
   ```
3. Open a pull request against `main`.

Valid categories are the Pager's native payload roots:
`user/*`, `recon/access_point`, `recon/client`, `alerts/*`.

Once merged (or while open), your payload is installable by its PR number.

---

## Repository layout

```text
.
├── README.md
├── CONTRIBUTING.md
├── LICENSE
├── index.json                       # number -> payload registry (the installer reads this)
├── payloads/
│   └── <category>/<name>/           # one directory per payload
│       ├── payload.sh
│       └── ...
└── themes/
    └── <name>/                      # Pager UI themes (theme.json + components + assets)
```

---

## Themes

This repo also hosts community **Pager themes** under `themes/`. Copy a theme
directory into `/root/themes/` (or `/mmc/root/themes/`) on the Pager, then pick
it under **Settings → General → Theme**.

| Theme | Description |
| --- | --- |
| Darkseclabz Glitch | Glitch-art wargames variant |
| Darksec Flipper | Flipper Zero monochrome dashboard (dolphin artwork) |
| Darksec Skeleton | Original pixel-art skeleton dashboard |
| Darkseclabz Numeric | 1990s alphanumeric-pager style (olive LCD, segmented menu) |

Theme PRs go to
[hak5/wifipineapplepager-themes](https://github.com/hak5/wifipineapplepager-themes).

---

## Legal

For authorized security testing, research, and education only. Not affiliated
with or endorsed by Hak5. Maintainers and contributors accept no liability for
misuse or damage.
