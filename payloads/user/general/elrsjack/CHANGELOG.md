# Changelog

## 1.0.0

- Initial Pager release.
- Port of the published Fox-IT ExpressLRS 900M link attack to the Glytch Mesh Mod SX1262.
- Pure-stdlib SX1262 SPI driver (no cross-compilation, no third-party packages).
- OTA4/OTA8 sync packet parse/build with ELRS CRC validation.
- FHSS seed brute force from observed hop timing; reports the known 2-candidate LCG ambiguity honestly.
- Wordlist binding-phrase recovery with exact MD5-tail confirmation.
- Bench-only sync probe — no channel/RCDATA packets, no actuator control.
- 480x222 Pager UI with six screens.
- 34 hardware-free tests, `capcheck`, `selftest`, headless UI smoke test.
- `payload.sh` stops `meshtasticd` and restores it on exit.
