# FTKRACK

**802.11r Fast Transition key-reinstallation payload for the WiFi Pineapple Pager**

FTKRACK eavesdrops on an 802.11r WPA2 network, captures a valid Fast
Transition Reassociation Request, replays that frame verbatim to the AP, and
reports a key reinstallation **only** when the AP's own behaviour proves it:
a status-0 reassociation response after the replay followed by CCMP packet
number reuse or regression in AP-to-client data frames.

This is CVE-2017-13082 (AP-side KRACK with 802.11r), a different bug and a
different attack surface from classic 4-way-handshake KRACK.

> **Authorized testing only.** Use on an AP and client you own or have explicit
> written permission to test. Never point this at third-party networks.

---

## Hard constraints

State these before deploying:

| Constraint | Detail |
|---|---|
| Firmware | Pager `2.0.0-stable+`, real 480x222 display |
| Interface | MT7921 **already in radiotap monitor mode** on `wlan1mon` (ARPHRD 803). FTKRACK does not change interface mode |
| Injection | One frame type only: the captured 802.11 management frame, byte-for-byte. No data-frame injection is assumed |
| Hardware | No Mesh Mod, no extra radio, no cross-compiled helper, no third-party Python packages |
| Scope | WPA2 with 802.11r enabled and vulnerable to CVE-2017-13082. WPA3-only, PMF-only (802.11w required), and patched APs produce no proof |
| MIC | A passive observer cannot verify the FTIE MIC (PTK unknown). Structural validity + AP response is the authenticity test |
| Validation | No live AP/client and no Pager hardware were available during development. Everything is hardware-free mocks; no real-world success is claimed |

---

## Catalog novelty

Checked against the official Hak5 payload library (966 tree paths) and the
Unleashed catalog: **zero** entries for `krack`, `80211r`, or `fast transition`.
Classic EvilPortal/Responder credential capture and handshake tools do exist
upstream; FTKRACK is not a copy or re-skin of those.

---

## Install

```sh
scp -r ftkrack root@172.16.52.1:/root/payloads/user/interception/
ssh root@172.16.52.1 'chmod +x /root/payloads/user/interception/ftkrack/payload.sh'
```

Payload Manager → **user / interception / ftkrack**.

`payload.sh` refuses to start if `wlan1mon` is missing or is not ARPHRD type
803. Put the MT7921 into monitor mode from the Pineapple UI before launching.

---

## On-device workflow

| Screen | Action |
|---|---|
| INTRO | **A** to authorize |
| TARGET | **U/D** choose interface, **A** open monitor, **B** lock target from capture |
| CAPTURE | **A** sniff 10 s, **B** clear evidence |
| REPLAY | **U/D** set replay count (1/3/5/10), **A** replay |
| PROOF | **A** verify evidence, **B** clear |
| LOG | engine log tail |

Operator sequence:

1. Put `wlan1mon` in monitor mode; select the channel the target FT AP uses.
2. INTRO → **A**.
3. TARGET → **A** (verify `MON=OK`).
4. CAPTURE → **A** while a client performs an 802.11r transition. Wait for
   `FT reassoc requests >= 1`.
5. REPLAY → **A**.
6. PROOF → **A**. Only `CONFIRMED` is a positive result.

---

## Evidence model (no fake success)

`PROOF CONFIRMED` requires **all four**, each from real observed data:

1. A structurally valid FT Reassociation Request was captured:
   MDIE (ID 54) + FTIE (ID 55) with non-zero MIC, SNonce and ANonce.
2. At least one whole replay frame was accepted by the kernel socket write.
   Failed writes are counted as write errors.
3. A Reassociation Response with status 0 from the target AP, for the **same
   station**, was received inside the 12-second window after replay.
4. A CCMP packet number from the AP was reused or regressed after replay.
   PNs are tracked per (AP, station, QoS TID), so traffic to a different client
   or a quiet queue cannot be mistaken for a reset. MAC-layer retransmissions
   are excluded as well.

If any condition is missing, the UI shows `UNCONFIRMED` with the specific
reason. Injection alone, capture alone, or a response alone never produce a
positive result.

---

## What the tool does not do

* It does not crack the PSK, decrypt captures offline, or forge a 4-way
  handshake.
* It does not generate data frames, EAPOL frames, deauthentication floods, or
  channel packets.
* It does not claim arbitrary frame injection against the AP; the replayed
  management frame is the only transmit.
* It does not target vehicles, RC links, or safety-critical systems.

---

## Development / test

```sh
python3 ftkrack.py capcheck
python3 ftkrack.py selftest
python3 ftkrack.py vectors
python3 -m unittest discover -s tests -v
python3 ft/ui.py --headless --sample --frames 6
```

All of the above run without a Pager, a monitor interface, or an AP. The
selftest uses `MockInjector` and synthetic 802.11 frames.

---

## Protocol notes

* FTIE (ID 55): MIC Control (2), MIC (16), SNonce (32), ANonce (32), optional
  subelements. MDIE (ID 54): MDID (2), FT capability/policy (1).
* CCMP header (8 bytes): `PN0, PN1, res0, key_id/ext_iv, PN2, PN3, PN4, PN5`.
  PN is the 48-bit little-endian composition of PN0/1/2/3/4/5.
* Radiotap injection header: minimal 8-byte header, version 0, `it_len=8`,
  present bitmap 0. mac80211 marks frames from a monitor interface as injected
  itself. Radiotap `TX_FLAGS` bit `0x0008` is `NOACK` (not "injected") and is
  deliberately not set, so the replayed unicast frame can still be ACKed.
* Reference: w1.fi advisory `2017-1` and the KRACK paper
  (https://papers.mathyvanhoef.com/ccs2017.pdf), CVE-2017-13082.

---

## License

See `LICENSE`.
