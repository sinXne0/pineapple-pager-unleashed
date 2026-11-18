# Changelog

## 1.0.0

- Initial SHARD payload.
- Pure-Python radiotap + 802.11 QoS A-MSDU frame builder (CVE-2020-24588).
- AF_PACKET raw-socket injection on `wlan1mon` with an on-device capability probe.
- Recon/DHCP-based target discovery with DFS/6 GHz/WPA3-PMF constraint checks.
- Attack modes: generic A-MSDU canary, injected DNS response, ICMP echo.
- 480x222 Pager UI with INTRO, TARGETS, PLAN, INJECT and LOG screens.
- Separate engine/UI processes over JSON state and command files.
- Authorization gate before any radio action.
- JSONL loot for injections and verification results.
- Hardware-free unit tests and simulation mode.
