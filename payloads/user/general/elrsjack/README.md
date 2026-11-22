# ELRSJACK

**ELRS 900M link credential recovery from the WiFi Pineapple Pager, using the Glytch Mesh Mod's SX1262.**

ELRSJACK parks the Mesh Mod's LoRa radio on an ExpressLRS 900 MHz sync channel, captures one CRC-valid sync packet, then uses observed hop timing to brute-force the FHSS seed and recover the link's binding phrase from a wordlist. It is a port of the published Fox-IT/NCC Group ExpressLRS link-hijack research to the Pager, reduced to the **credential/loot** portion.

> **AUTHORIZED BENCH TESTING ONLY.** Use on an ELRS link and receiver you own or have explicit written permission to test. **Never point this at a live aircraft or vehicle.** ELRSJACK deliberately implements no channel/RCDATA packets, so it cannot move any actuator.

---

## Hard constraints (read before deploying)

| Constraint | Detail |
|---|---|
| Hardware | Glytch Mesh Mod SX1262 on the ch341 SPI bridge (`VID 1A86:5512`). Nothing else can receive 900 MHz ELRS here. |
| Service conflict | `meshtasticd` owns the SX1262. `payload.sh` stops it and restores it on exit. While it runs, ELRSJACK reports `NO RADIO`. |
| Band | Sub-GHz ELRS only (433 / 868 / 915 MHz). 2.4 GHz ELRS uses an SX1280 and is **not** supported. |
| Radio mismatch | ELRS 900M officially uses SX1276, not SX1262. The SX1262 LoRa sync-word register is not standardised, so the operator cycles candidates (`0x1212`, `0x1424`, `0x3444`, `0x0000`) with **B** in the SCAN screen. A packet is trusted only if the **ELRS OTA CRC** validates — never because the sync word matched. If none validate, the sync counter stays at 0 and nothing is claimed. |
| UID bytes | `UID[0]` and `UID[1]` are never transmitted. Recovery always reports them as `00 00`. Only `UID[2..5]` are recovered. |
| Ambiguity | The ELRS LCG discards the top seed bit, so `UID[2]` bit 7 is normally ambiguous (two candidates). The wordlist cracker disambiguates by exact MD5 tail; without a match the UI says **AMBIGUOUS**, never "recovered". |
| Wordlist | Phrase recovery only finds phrases present in `data/binding-phrases.txt` (plus case/separator mutations). A random 16-character phrase will not be recovered. |
| Link probe | Sends a crafted **sync packet only**, to prove the recovered UID is accepted by an authorized bench receiver with no actuator attached. It generates no control data. |
| Validation | No live ELRS link, bench receiver, or Pager hardware was available. All 34 tests use mocked radios. No real-world success is claimed. |
| Blockers | No Mesh Mod, `meshtasticd` still running, wrong regulatory domain/air rate/sync word, 2.4 GHz link, or a strong random binding phrase. |

---

## The published weakness

Fox-IT/NCC Group (June 2022) showed that:

1. The binding phrase is MD5'd into a 6-byte UID: `MD5('-DMY_BINDING_PHRASE="' + phrase + '"')[:6]`. ExpressLRS documents it as anti-collision, not security.
2. Every sync packet leaks `UID[4]` and `UID[5]` in the clear, and the packet CRC is *initialised* from those same bytes, so the leak self-validates.
3. The FHSS sequence is seeded from `UID[2..5]`. With two bytes known, only 65 536 seeds remain.
4. Because ELRS hops once per packet at a known rate, the channels visited at fixed offsets from a sync packet identify the seed. The weak LCG (32-bit state, 15-bit output) makes the top seed bit irrecoverable, but the wordlist closes that gap.

ELRSJACK implements all four steps against OTA4/OTA8 sync packets from current ExpressLRS source, not a hand-waved approximation.

---

## Impact (what is actually recovered)

- **Credentials** — the FHSS seed and, when the phrase is weak or default, the plaintext binding phrase.
- **Network access** — a recovered UID lets an operator configure their own authorized transmitter for the same bench link (done outside ELRSJACK, with a normal ELRS transmitter).
- No physical control is implemented or implied.

---

## Install

Copy the whole `elrsjack/` folder into a Pager payload directory, e.g.:

```text
/root/payloads/user/general/elrsjack/
```

Requirements: `python3-light` and the Glytch Mesh Mod. No extra packages, no HackRF, no cross-compilation. `lib/` contains PAGERCTL for the 480x222 UI.

---

## Use

1. Stop Meshtastic manually if you want to inspect the radio first; the payload handles it otherwise.
2. Launch **ELRSJACK** from **Payloads → User Payloads** and accept the warning.
3. **RADIO** — select the target regulatory domain (`FCC915`, `EU868`, ...) and air rate. Press **B** in SCAN to cycle the sync-word candidate if nothing validates.
4. **SCAN** — press **A** for a 10-second capture. Watch `CRC-valid ELRS sync` climb above 0. If it stays at 0, stop: hardware, domain, rate, or sync word is wrong.
5. **TRACK** — press **A** to park on one channel and record hop offsets (the engine picks a channel adjacent to sync). Longer is better; 15–30 s is typical.
6. **UID** — press **A** to brute-force the seed. Expect 2 candidates. Press **B** to run the wordlist cracker; an exact MD5 match disambiguates and confirms the phrase.
7. **PROBE** — press **A** for the bench-only sync probe. `CONFIRMED` requires a downlink response; otherwise it stays `SENT / UNCONFIRMED`.
8. Power button to stop. `meshtasticd` is restored if it was running.

---

## Loot

```text
/root/loot/elrsjack/
├── elrsjack.log     engine/UI log
├── capture.json     raw/valid packet counts, last UID4/UID5
└── result.json      UID candidates, phrase confirmation, probe result
```

---

## Honest status

| Field | Set only when |
|---|---|
| `radio=spi` | a spidev node actually answered the SX1262 `GetStatus` command |
| `valid_sync_packets` | an OTA packet parsed **and** its ELRS CRC validated |
| `recovery.uid` | exactly one seed matched all hop observations, or a phrase matched one candidate |
| `phrase.confirmed` | an exact MD5 UID-tail match from the wordlist |
| `probe.confirmed` | a downlink packet was heard after the crafted sync probe |

There is no simulated success state anywhere in the payload.

---

## Testing (hardware-free)

```bash
python3 -m unittest discover -s tests -v   # 34 tests, all mocked
python3 elrsjack.py capcheck               # stdlib + protocol primitives
python3 elrsjack.py selftest               # capture -> recover -> crack end to end
python3 elrsjack.py vectors                # known-answer vectors
python3 elrs/ui.py --headless --sample --frames 5
```

---

## Files

| Path | Purpose |
|---|---|
| `payload.sh` | Launcher, auth gate, meshtasticd stop/restore, LED handling |
| `elrsjack.py` | Entry point (`engine`, `capcheck`, `selftest`, `vectors`) |
| `elrs/crypto.py` | Binding-phrase → UID MD5, CRC init, UID seed |
| `elrs/fhss.py` | ELRS LCG, 256-entry hop sequence, regulatory domains |
| `elrs/ota.py` | OTA4/OTA8 sync packet parse/build and CRC validation |
| `elrs/radio.py` | SX1262 pure-stdlib SPI driver + `MockRadio` |
| `elrs/capture.py` | Sync capture and FHSS-seed brute force |
| `elrs/crack.py` | Wordlist binding-phrase recovery |
| `elrs/engine.py` | State machine and honesty rules |
| `elrs/ui.py` | 480x222 Pager UI |
| `data/binding-phrases.txt` | Default weak-phrase wordlist |
| `tests/` | Hardware-free test suite |

---

## References

- [Fox-IT / NCC Group — ExpressLRS vulnerabilities allow hijack of control link](https://www.fox-it.com/nl-en/technical-advisory-expresslrs-vulnerabilities-allow-for-hijack-of-control-link/)
- [ExpressLRS source — config.cpp (UID derivation)](https://github.com/ExpressLRS/ExpressLRS/blob/master/src/lib/CONFIG/config.cpp)
- [ExpressLRS source — OTA.cpp (CRC/seed)](https://github.com/ExpressLRS/ExpressLRS/blob/master/src/lib/OTA/OTA.cpp)
- [ExpressLRS source — FHSS.cpp / random.cpp](https://github.com/ExpressLRS/ExpressLRS/tree/master/src/lib/FHSS)
- [RadioLib SX126x command/register definitions](https://github.com/jgromes/RadioLib/tree/master/src/modules/SX126x)

## License

GPLv3 — see [LICENSE](LICENSE).
