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

### Payload catalog

The number is the PR that added the payload and stays with it forever.

| # | Payload | Description |
| --- | --- | --- |
| 1 | VENUS | Flytrap rogue AP with spiderweb UI, captive portal and deauth lure |
| 2 | MIRRORCAST | mDNS/SSDP cast + print honeypot, print capture and castjack |
| 3 | IoTJACK | Kasa / MQTT / UPnP IGD / TR-064 / RTSP / PJL modules |
| 4 | PWRLVL9000 | Nine-tab pentest web console with XP leveling and handshake vault |
| 5 | GITGREP | GitHub and git secret hunter with 35+ detectors and masked reports |
| 6 | PHONEPHREAK | Phone-number OSINT, line type, link pack, QR handoff and bulk mode |
| 7 | SCALPEL | Channel-locked targeted handshake capture |
| 8 | EVILPORTAL | Evil captive portal / credential harvester with Flipper Zero templates |
| 10 | KEYSMITH | Derives ISP-default WPA keys from SSID+BSSID, verifies by handshake and shows the plaintext PSK |
| 12 | SHARD | Pager-only FragAttacks injector: A-MSDU frame injection into WPA2 clients without the PSK (CVE-2020-24588) |
| 14 | NULLGATE | Unauthenticated root RCE against UniFi OS consoles (CVE-2026-34908/34909/34910): secret-store dump and owner-token forge |
| 15 | ELRSJACK | ELRS 900M link credential recovery via the Mesh Mod SX1262: FHSS seed + binding phrase, bench-only probe |
| 16 | FTKRACK | 802.11r Fast Transition key reinstallation (CVE-2017-13082): replay a captured FT reassociation request and confirm AP PTK/TK reinstall from CCMP PN reuse |

Install #10 with:

```sh
scp -r payloads/user/reconnaissance/keysmith \
  root@172.16.42.1:/root/payloads/user/reconnaissance/
ssh root@172.16.42.1 'chmod +x /root/payloads/user/reconnaissance/keysmith/payload.sh /root/payloads/user/reconnaissance/keysmith/keysmith.py /root/payloads/user/reconnaissance/keysmith/install_pkg.py /root/payloads/user/reconnaissance/keysmith/lib/udhcpc.script'
```

Install #12 with:

```sh
scp -r payloads/user/reconnaissance/shard \
  root@172.16.52.1:/root/payloads/user/reconnaissance/
ssh root@172.16.52.1 'chmod +x /root/payloads/user/reconnaissance/shard/payload.sh /root/payloads/user/reconnaissance/shard/shard.py /root/payloads/user/reconnaissance/shard/sd/ui.py /root/payloads/user/reconnaissance/shard/install_pkg.py'
```

SHARD injects only on 2.4 GHz / non-DFS 5 GHz, cannot attack WPA3/PMF
networks, and probes injection capability on-device before reporting success.

Install #14 with:

```sh
scp -r payloads/user/exfiltration/nullgate \
  root@172.16.52.1:/root/payloads/user/exfiltration/
ssh root@172.16.52.1 'chmod +x /root/payloads/user/exfiltration/nullgate/payload.sh /root/payloads/user/exfiltration/nullgate/nullgate.py /root/payloads/user/exfiltration/nullgate/sd/ui.py'
```

NULLGATE needs L3 reachability to a vulnerable UniFi OS console on TCP 11443.
It confirms execution only via a callback nonce and was validated against a
faithful local mock — no live vulnerable appliance was available during
development. Patched consoles are reported as `PATCHED`, never exploited.

Install #15 with:

```sh
scp -r payloads/user/general/elrsjack \
  root@172.16.52.1:/root/payloads/user/general/
ssh root@172.16.52.1 'chmod +x /root/payloads/user/general/elrsjack/payload.sh /root/payloads/user/general/elrsjack/elrsjack.py /root/payloads/user/general/elrsjack/elrs/ui.py'
```

ELRSJACK needs the Glytch Mesh Mod (SX1262 on ch341 SPI) and stops `meshtasticd`
while running. Sub-GHz ELRS only; 2.4 GHz links are not supported. It recovers
the FHSS seed and weak binding phrase — **no flight/vehicle control packets are
generated**, and the bench probe generates no actuator input. Sync-word
behavior on the SX1262 is uncertain, so candidates are cycled manually and only
OTA-CRC-valid packets are trusted. Validated with mocked radios only; no live
ELRS link or Pager hardware was available.

Install #16 with:

```sh
scp -r payloads/user/interception/ftkrack \
  root@172.16.52.1:/root/payloads/user/interception/
ssh root@172.16.52.1 'chmod +x /root/payloads/user/interception/ftkrack/payload.sh /root/payloads/user/interception/ftkrack/ftkrack.py /root/payloads/user/interception/ftkrack/ft/ui.py'
```

FTKRACK requires the MT7921 to already be in radiotap monitor mode on `wlan1mon`
(ARPHRD 803) and only replays the captured 802.11r reassociation frame verbatim.
It confirms a key reinstallation only from an accepted replay write plus a
status-0 response for the same station plus per-(AP, station, TID) CCMP PN reuse.
No Mesh Mod or extra hardware is needed. No live 802.11r AP/client or Pager
hardware was available during development; all validation was mocked.

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
    ├── README.md                    # theme catalog, install guide and changelog
    ├── zips/                        # prebuilt, flat theme archives
    └── <name>/                      # Pager UI themes (theme.json + components + assets)
```

---

## Themes

This repo also hosts community **Pager themes** under `themes/`. Copy a theme
directory into `/root/themes/` (or `/mmc/root/themes/`) on the Pager, then pick
it under **Settings → General → Theme**.

Theme folders, install steps, the full catalog, prebuilt zips and the changelog
are in [`themes/README.md`](themes/README.md).

| Theme | Description |
| --- | --- |
| Darkseclabz Glitch | Glitch-art wargames variant |
| Darksec Flipper | Flipper Zero monochrome dashboard (dolphin artwork) |
| Darksec Skeleton | Original pixel-art skeleton dashboard |
| Darkseclabz Numeric | 1990s alphanumeric-pager style (olive LCD, segmented menu) |
| Darkseclabz Desktop | macOS Tahoe-inspired glass dock dashboard |
| Darkseclabz Hadal Station | Underwater research-station dashboard |
| 40k | Warhammer 40K / INQUISITOR six-state wheel |
| Edgerunners Detail Glitch | Cyberpunk: Edgerunners detail/glitch artwork set |
| Edgrunners | Edgerunners Neon Afterlife - Night City districts edition |

Theme PRs go to
[hak5/wifipineapplepager-themes](https://github.com/hak5/wifipineapplepager-themes).

---

## Legal

For authorized security testing, research, and education only. Not affiliated
with or endorsed by Hak5. Maintainers and contributors accept no liability for
misuse or damage.
