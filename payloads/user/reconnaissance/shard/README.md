# SHARD

**Pager-only 802.11 fragment-injection payload for the WiFi Pineapple Pager.**

SHARD is a pocket implementation of the FragAttacks family — specifically
**CVE-2020-24588**, the A-MSDU aggregation injection. It crafts a plaintext
QoS data frame with the *A-MSDU Present* flag set in the QoS Control field.
That flag lives outside the CCMP-encrypted body of a normal frame, so a
vulnerable WPA2 client accepts the frame as if it came from its access point
and processes the encapsulated IP packet — **without the attacker ever
knowing the PSK**.

Everything runs on the Pager itself. No laptop, no second radio, no external
adapter.

> **Authorized testing only.** Inject packets only into networks and clients
> you own or have explicit written permission to test.

---

## Hardware constraints (read this first)

These are hard limits confirmed from Hak5 documentation, firmware internals,
and the Pager's hardware — not guesses:

| Constraint | Why |
|---|---|
| **2.4 GHz and non-DFS 5 GHz only** | The firmware blocks injection on DFS and all 6 GHz channels for regulatory reasons. |
| **No WPA3 / 802.11w PMF targets** | Protected Management Frames defeat injected frames. WPA3 on 6 GHz is mandatory. |
| **Client must be vulnerable** | CVE-2020-24588 affects many but not all WPA2 clients. Patched clients reject the frame. |
| **Target data required** | Needs AP BSSID, client MAC, and channel from the Pager's recon engine. |
| **Interface must be free** | `wlan1mon` is shared with PineAP/recon; SHARD locks it to the target channel during injection. |
| **Data-frame injection is not guaranteed on every firmware** | Management-frame injection (deauth) is confirmed; arbitrary data frames depend on the driver. SHARD probes capability and reports it — it never claims unverified success. |

The attack radio is the **MT7921AU** (`wlan1mon`, `mt7921u` driver, mac80211
monitor mode). SHARD injects through a Linux `AF_PACKET` raw socket — the same
mechanism `aireplay-ng` uses — so there is no scapy/opkg dependency.

---

## Screens

```text
INTRO     authorization gate + constraint summary
TARGETS   recon-derived target list (BSSID, channel, client, status)
PLAN      selected target, attack mode, capability probe
INJECT    fire the fragment, view last raw frame
LOG       engine/attack log
```

Buttons:

- **Left / Right** — change screen (or change attack mode in PLAN)
- **Up / Down** — move the target selection / cycle attack mode
- **A** — authorize, discover, select target, probe, or inject
- **B** — back / verify

Attack modes:

- `amsdu` — generic ICMP canary in an A-MSDU (best general test)
- `dns` — inject a crafted DNS response for a canary domain
- `icmp` — inject a raw ICMP echo request

---

## How it works

1. **Authorize** — explicit gate before any radio action.
2. **Discover** — read the Pager's recon logs, or passively sniff data frames
   on `wlan1mon`. Targets on DFS/6 GHz or WPA3/PMF are marked BLOCKED.
3. **Probe** — test raw-socket injection and, if present, run `aireplay-ng
   --test`. Capability is reported, never assumed.
4. **Plan** — pick the target and attack mode. SHARD locks `wlan1mon` to the
   target channel.
5. **Inject** — build `radiotap + 802.11 QoS Data + A-MSDU(802.3/IP)` and send
   it in one raw-socket write.
6. **Verify** — capture with `tcpdump` for a client response. A canary is only
   reported as verified if a response is actually observed.

The frame is built in pure Python (`sd/frames.py`): radiotap, 802.11 MAC
header, QoS Control with `A-MSDU Present`, LLC/SNAP, and an IPv4 packet with a
valid checksum. No third-party modules.

---

## Install

Copy the folder to:

```text
/root/payloads/user/reconnaissance/shard/
```

Launch from **Payloads ▸ user ▸ reconnaissance ▸ SHARD**. `payload.sh`
self-locates, so the parent directory name can be changed.

Dependencies:

- `python3-light` (required)
- bundled `lib/libpagerctl.so` (required for the Pager display)
- `iw` (required to lock the channel)
- `tcpdump` + `aireplay-ng` (optional — enable on-air verification only)

Environment overrides:

```text
SHARD_IFACE    monitor interface, default wlan1mon
SHARD_STATE    state JSON path
SHARD_CMD      command JSONL path
SHARD_LOOT     loot directory
SHARD_SIM=1    run the full attack flow with simulated hardware (no radio)
```

---

## Tests

```sh
python3 -m unittest discover -s tests -v
python3 shard.py selftest
python3 sd/ui.py --headless --sample --frames 3
```

No radio, no Pager, and no third-party modules are required for the test
suite. `SHARD_SIM=1` runs the complete engine flow without touching hardware.

---

## Loot

```text
/root/loot/shard/injections.jsonl  one record per injected frame (incl. raw hex)
/root/loot/shard/results.jsonl     verification results
/root/loot/shard/shard.log         engine and UI log
```

---

## Credits

The frame builders, engine, and UI are original. The Pager display library is
the firmware's own `libpagerctl.so` shipped with a ctypes wrapper from the
Pager payload examples. The underlying vulnerability is CVE-2020-24588 from
the FragAttacks research by Mathy Vanhoef and Frank Piessens.
