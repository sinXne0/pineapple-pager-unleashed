# Changelog

## 1.0.0

- Initial Pager port of the UniFi OS unauthenticated root chain
  (CVE-2026-34908 / 34909 / 34910).
- Verbatim-URI HTTP transport preserving the encoded traversal primitive.
- Non-destructive safety probe with VULNERABLE / PATCHED / INCONCLUSIVE /
  UNAFFECTED verdicts.
- Callback-based confirmation: stages are marked confirmed only when the
  target calls back with the matching nonce; HTTP 200 alone is never success.
- Local subnet discovery of TCP 11443 consoles and UniFi OS fingerprinting.
- RCE proof stage, arbitrary file read, and secret-store loot exfiltration via
  passwordless `sudo chmod`.
- Offline HS256 owner-token forge from the stolen signing key, with an
  authenticated API check for persistence.
- 480x222 Pager UI with five screens and honest stage status.
- 23 hardware-free tests including a full end-to-end chain against a local
  mock console.
