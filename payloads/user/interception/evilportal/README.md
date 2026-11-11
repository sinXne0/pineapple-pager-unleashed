# EVILPORTAL — Evil Captive Portal

An evil captive portal for the WiFi Pineapple Pager. It serves an open rogue
access point with a themed login page (using Flipper Zero Evil Portal HTML
templates) and captures the credentials that devices submit.

> **Authorized testing only.** This impersonates a Wi-Fi network and logs
> credentials. Use it only on networks you own or have written permission to
> test.

## What it does

1. Brings up an open rogue AP with the SSID you choose.
2. Serves a captive portal (a fake login page) to anyone who connects.
3. Redirects captive-portal probes and wildcard DNS to the portal.
4. Captures every `email` + `password` submitted to the form.

## Requirements

- `python3-light` (engine uses only `python3-light` stdlib).
- `hostapd` and `iw` (standard on current firmware).
- No `dnsmasq` — ships its own raw-socket DHCP and wildcard DNS.

## Install

```sh
scp -r evilportal root@172.16.42.1:/root/payloads/user/interception/
ssh root@172.16.42.1 'chmod +x /root/payloads/user/interception/evilportal/payload.sh'
```

Run **EVILPORTAL** from **Payloads → User Payloads**. Pick an SSID and a
portal theme, and it's live. Press **B** to stop.

## Portals

`portals/` contains Flipper Zero Evil Portal templates (all self-contained
HTML, posting to `/get` with `email`/`password`):

`Google_Modern`, `Better_Google_Mobile`, `Facebook`, `Amazon`, `Microsoft`,
`apple`, `AT&T`, `T_Mobile`, `Verizon`, `Spectrum`, `Starlink`, `Twitter`,
`Twitch`, `CoxWifi`.

To add your own, drop a self-contained `.html` into `portals/`. The form
should submit to `/get` (GET) with `name="email"` and `name="password"`
fields — or POST to any path; the engine captures both.

## Loot

`/root/loot/evilportal/creds.jsonl` — one JSON line per captured credential:

```json
{"t":1700000000.0,"ip":"192.168.69.10","email":"user@example.com","password":"hunter2","ua":"..."}
```

Written mode `0600`.

## Portal templates credit

Templates sourced from
[bigbrodude6119/flipper-zero-evil-portal](https://github.com/bigbrodude6119/flipper-zero-evil-portal)
(MIT).

## Legal

For authorized security testing and education only.
