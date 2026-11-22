# Changelog

## 1.0.0

- Initial FTKRACK release for Pager `2.0.0-stable+`.
- Radiotap capture parsing (`ft/dot11.py`).
- 802.11 management parsing for FT Reassociation Request/Response, MDIE (54),
  FTIE (55), and CCMP 48-bit PN extraction (`ft/dot11.py`).
- Verbatim replay of a captured FT reassociation frame through the MT7921
  monitor interface (`ft/inject.py`).
- Passive capture engine with target locking and per-(AP, station, TID) AP PN
  tracking; MAC retransmissions and other stations' frames/responses are
  excluded from evidence (`ft/capture.py`).
- Minimal 8-byte radiotap injection header (no `NOACK` bit) so the replayed
  unicast management frame can be acknowledged (`ft/dot11.py`).
- Evidence-gated engine state machine: no success without capture + accepted
  replay + status-0 response after replay + PN reuse/regression
  (`ft/engine.py`).
- 480x222 PAGERCTL UI with INTRO, TARGET, CAPTURE, REPLAY, PROOF and LOG
  screens (`ft/ui.py`).
- Hardware-free suite: 47 unit tests, `capcheck`, `selftest`, `vectors`, and
  headless UI render smoke test.
- Loot capture/result JSON plus the raw captured reassociation frame.
