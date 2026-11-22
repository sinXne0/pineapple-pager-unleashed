"""Hardware-free test suite for FTKRACK.

No Pager, no monitor interface, no live 802.11r AP, no injection.  Every radio
interaction is mocked.  Nothing in this suite claims real-world success.
"""

from __future__ import annotations

import os
import struct
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from ft import capture, dot11, engine, inject  # noqa: E402

AP = bytes.fromhex("a45e60112233")
STA = bytes.fromhex("3c71bfaabbcc")
OLD_AP = bytes.fromhex("a45e60114444")


def frames():
    req = dot11.build_reassoc_req(AP, STA, OLD_AP, "CORP-FT", mdid=0x1234)
    resp = dot11.build_reassoc_resp(AP, STA, status=0, aid=2)
    before = [dot11.build_ccmp_data(AP, STA, STA, pn) for pn in (9000, 9001, 9002)]
    after = [dot11.build_ccmp_data(AP, STA, STA, pn) for pn in (1, 9000)]
    return req, resp, before, after


class Dot11Tests(unittest.TestCase):
    def test_radiotap_inject_header_bytes(self):
        self.assertEqual(dot11.build_radiotap_inject(),
                         bytes.fromhex("0000080000000000"))

    def test_radiotap_inject_has_no_optional_fields(self):
        info = dot11.parse_radiotap(dot11.build_radiotap_inject())
        self.assertIsNotNone(info)
        self.assertEqual(info["present"][0], 0)
        # 0x0008 in radiotap TX_FLAGS would be NOACK; we must not send it.
        self.assertEqual(info["tx_flags"], 0)

    def test_radiotap_capture_metadata(self):
        req, _, _, _ = frames()
        buf = dot11.build_capture_buffer(req, channel_hz=5180_000_000, signal_dbm=-58)
        stripped, info = dot11.strip_radiotap(buf)
        self.assertEqual(stripped, req)
        self.assertEqual(info["channel_hz"], 5180_000_000)
        self.assertEqual(info["signal_dbm"], -58)

    def test_malformed_radiotap_rejected(self):
        self.assertIsNone(dot11.parse_radiotap(b"\x01\x00\x08\x00\x00\x00\x00\x00"))
        self.assertIsNone(dot11.parse_radiotap(b"\x00\x00\xff\x00\x00\x00\x00\x00"))

    def test_reassoc_req_ft_fields(self):
        req, _, _, _ = frames()
        parsed = dot11.parse_reassoc_req(dot11.parse_dot11(req))
        self.assertTrue(parsed["ft_valid"])
        self.assertEqual(parsed["bssid"], dot11.mac(AP))
        self.assertEqual(parsed["sta"], dot11.mac(STA))
        self.assertEqual(parsed["mdie"]["mdid"], 0x1234)
        self.assertEqual(len(parsed["ftie"]["snonce"]), 32)
        self.assertEqual(len(parsed["ftie"]["anonce"]), 32)
        self.assertEqual(len(parsed["ftie"]["mic"]), 16)

    def test_non_ft_reassoc_req_is_not_ft_valid(self):
        req = dot11.build_reassoc_req(AP, STA, OLD_AP, "plain")
        # Strip both 802.11r IEs by rebuilding a body without them.
        body = req[24:24 + 4 + 6 + 2 + 5]  # capability+listen+current+SSID IE
        fc = (dot11.TYPE_MGT << 2) | (dot11.MGT_REASSOC_REQ << 4)
        plain = (struct.pack("<HH6s6s6sH", fc, 0, AP, STA, AP, 0) + body)
        parsed = dot11.parse_reassoc_req(dot11.parse_dot11(plain))
        self.assertIsNotNone(parsed)
        self.assertFalse(parsed["ft_valid"])

    def test_short_ftie_rejected(self):
        self.assertIsNone(dot11.parse_ftie(bytes(81)))

    def test_reassoc_response_success_and_failure(self):
        _, resp, _, _ = frames()
        ok = dot11.parse_reassoc_resp(dot11.parse_dot11(resp))
        self.assertTrue(ok["success"])
        self.assertEqual(ok["status"], 0)
        denied = dot11.parse_reassoc_resp(
            dot11.parse_dot11(dot11.build_reassoc_resp(AP, STA, status=17)))
        self.assertFalse(denied["success"])

    def test_mdie_builder_is_three_bytes(self):
        req, _, _, _ = frames()
        parsed = dot11.parse_reassoc_req(dot11.parse_dot11(req))
        self.assertEqual(len(parsed["mdie"]["raw"]), 3)

    def test_qos_tid_and_retry_are_extracted(self):
        frame = dot11.build_ccmp_data(AP, STA, STA, 42, tid=5, retry=True)
        parsed = dot11.parse_ccmp_data(dot11.parse_dot11(frame))
        self.assertEqual(parsed["tid"], 5)
        self.assertTrue(parsed["retry"])

    def test_ccmp_pn_little_endian_layout(self):
        pn = 0x010203040506
        frame = dot11.build_ccmp_data(AP, STA, STA, pn)
        ccmp = frame[26:34]
        self.assertEqual(ccmp, bytes.fromhex("0605002004030201"))
        parsed = dot11.parse_ccmp_data(dot11.parse_dot11(frame))
        self.assertEqual(parsed["pn"], pn)
        self.assertEqual(parsed["transmitter"], dot11.mac(AP))

    def test_mac_parse_and_format(self):
        self.assertEqual(dot11.parse_mac("A4:5E:60:11:22:33"), AP)
        self.assertIsNone(dot11.parse_mac("not-a-mac"))


class CaptureTests(unittest.TestCase):
    def test_capture_valid_ft_request_and_autotarget(self):
        req, _, _, _ = frames()
        cap = capture.CaptureEngine()
        event = cap.feed(dot11.build_capture_buffer(req))
        self.assertTrue(event["ft_valid"])
        self.assertTrue(cap.ft_request is not None)
        self.assertEqual(cap.target_bssid, dot11.mac(AP))
        self.assertEqual(cap.ft_request["mdie"]["mdid"], 0x1234)

    def test_no_valid_request_means_no_capture(self):
        # A zero MIC is structurally invalid; a passive observer must not
        # treat it as a replayable FT request.
        req = dot11.build_reassoc_req(AP, STA, OLD_AP, "CORP-FT",
                                      mdid=0x1234, mic=bytes(16))
        cap = capture.CaptureEngine()
        cap.feed(dot11.build_capture_buffer(req))
        self.assertIsNone(cap.ft_request)
        self.assertFalse(cap.proof()["confirmed"])

    def test_pn_reuse_requires_replay_phase(self):
        req, _, before, after = frames()
        cap = capture.CaptureEngine()
        for f in [req] + before + after:
            cap.feed(dot11.build_capture_buffer(f))
        self.assertEqual(cap.pn_reuse_exact, 0)
        self.assertEqual(cap.pn_regression, 0)
        self.assertFalse(cap.proof()["confirmed"])

    def test_pn_reuse_after_replay(self):
        req, _, before, after = frames()
        cap = capture.CaptureEngine()
        for f in [req] + before:
            cap.feed(dot11.build_capture_buffer(f))
        self.assertEqual(cap.snapshot()["pn_before_max"], 9002)
        cap.note_replay(1)
        for f in after:
            cap.feed(dot11.build_capture_buffer(f))
        self.assertGreaterEqual(cap.pn_reuse_exact, 1)
        self.assertGreaterEqual(cap.pn_regression, 1)
        self.assertFalse(cap.proof()["confirmed"])  # still needs AP response

    def test_proof_needs_all_four_conditions(self):
        req, resp, before, after = frames()
        cap = capture.CaptureEngine()
        for f in [req] + before:
            cap.feed(dot11.build_capture_buffer(f))
        cap.note_replay(1)
        cap.feed(dot11.build_capture_buffer(resp))
        for f in after:
            cap.feed(dot11.build_capture_buffer(f))
        proof = cap.proof()
        self.assertTrue(proof["confirmed"])
        self.assertEqual(proof["reasons"], [])

    def test_low_pn_on_a_different_tid_is_not_reuse(self):
        """A quiet TID is not evidence of a reset of a busy TID's PN."""
        req, _, _, _ = frames()
        cap = capture.CaptureEngine()
        cap.feed(dot11.build_capture_buffer(req))
        for pn in (9000, 9001, 9002):
            cap.feed(dot11.build_capture_buffer(
                dot11.build_ccmp_data(AP, STA, STA, pn, tid=0)))
        cap.note_replay(1)
        cap.feed(dot11.build_capture_buffer(
            dot11.build_ccmp_data(AP, STA, STA, 10, tid=3)))
        self.assertEqual(cap.pn_reuse_exact, 0)
        self.assertEqual(cap.pn_regression, 0)
        self.assertFalse(cap.proof()["confirmed"])

    def test_mac_retransmissions_are_not_reuse(self):
        req, _, _, _ = frames()
        cap = capture.CaptureEngine()
        cap.feed(dot11.build_capture_buffer(req))
        cap.feed(dot11.build_capture_buffer(
            dot11.build_ccmp_data(AP, STA, STA, 9000, tid=0)))
        cap.note_replay(1)
        cap.feed(dot11.build_capture_buffer(
            dot11.build_ccmp_data(AP, STA, STA, 9000, tid=0, retry=True)))
        self.assertEqual(cap.retries_ignored, 1)
        self.assertEqual(cap.pn_reuse_exact, 0)

    def test_pn_to_a_second_client_is_not_reuse(self):
        """A different STA has a different PTK and its own PN sequence."""
        req, resp, before, after = frames()
        other = bytes.fromhex("001122334455")
        cap = capture.CaptureEngine()
        cap.feed(dot11.build_capture_buffer(req))
        for f in before:
            cap.feed(dot11.build_capture_buffer(f))
        cap.note_replay(1)
        cap.feed(dot11.build_capture_buffer(resp))
        cap.feed(dot11.build_capture_buffer(
            dot11.build_ccmp_data(AP, other, other, 1, tid=0)))
        self.assertEqual(cap.pn_reuse_exact, 0)
        self.assertEqual(cap.pn_regression, 0)
        self.assertFalse(cap.proof()["confirmed"])

    def test_response_for_another_station_does_not_count(self):
        req, _, before, after = frames()
        other_sta = bytes.fromhex("001122334455")
        cap = capture.CaptureEngine()
        cap.feed(dot11.build_capture_buffer(req))
        for f in before:
            cap.feed(dot11.build_capture_buffer(f))
        cap.note_replay(1)
        cap.feed(dot11.build_capture_buffer(
            dot11.build_reassoc_resp(AP, other_sta, status=0)))
        for f in after:
            cap.feed(dot11.build_capture_buffer(f))
        self.assertFalse(cap.proof()["confirmed"])

    def test_response_after_window_does_not_count(self):
        req, resp, before, after = frames()
        cap = capture.CaptureEngine()
        cap.feed(dot11.build_capture_buffer(req))
        for f in before:
            cap.feed(dot11.build_capture_buffer(f))
        cap.note_replay(1)
        cap.replay_window_until = time.monotonic() - 1
        cap.feed(dot11.build_capture_buffer(resp))
        for f in after:
            cap.feed(dot11.build_capture_buffer(f))
        self.assertFalse(cap.proof()["confirmed"])

    def test_target_lock_rejects_other_ap_request(self):
        req, _, _, _ = frames()
        cap = capture.CaptureEngine("00:11:22:33:44:55")
        cap.feed(dot11.build_capture_buffer(req))
        self.assertIsNone(cap.ft_request)
        self.assertEqual(cap.target_bssid, "00:11:22:33:44:55")

    def test_wrong_ap_response_does_not_count(self):
        req, _, before, after = frames()
        other_resp = dot11.build_reassoc_resp(bytes.fromhex("001122334455"), STA)
        cap = capture.CaptureEngine()
        for f in [req] + before:
            cap.feed(dot11.build_capture_buffer(f))
        cap.note_replay(1)
        cap.feed(dot11.build_capture_buffer(other_resp))
        for f in after:
            cap.feed(dot11.build_capture_buffer(f))
        self.assertFalse(cap.proof()["confirmed"])


class InjectorTests(unittest.TestCase):
    def test_mock_injector_records_whole_frames(self):
        req, _, _, _ = frames()
        wire = dot11.build_radiotap_inject() + req
        mock = inject.MockInjector()
        self.assertTrue(mock.inject(wire))
        self.assertEqual(mock.injected, [wire])

    def test_failed_write_is_honest(self):
        mock = inject.MockInjector(inject_ok=False)
        self.assertFalse(mock.inject(b"\x00" * 8))
        self.assertEqual(mock.injected, [])

    def test_absent_interface_is_not_monitor(self):
        self.assertFalse(inject.is_monitor("wlan1mon-definitely-not-real"))


class EngineTests(unittest.TestCase):
    def make_engine(self, feeds=None, inject_ok=True):
        return engine.Engine(
            injector=inject.MockInjector(feeds=feeds or [], inject_ok=inject_ok),
            state_path=tempfile.mktemp(), cmd_path=tempfile.mktemp(),
            loot=tempfile.mktemp(),
        )

    def test_authorization_gate(self):
        eng = self.make_engine()
        eng.handle({"cmd": "iface", "value": "wlan9mon"})
        self.assertEqual(eng.state["iface"], "wlan1mon")
        eng.handle({"cmd": "authorize"})
        eng.handle({"cmd": "iface", "value": "wlan9mon"})
        self.assertEqual(eng.state["iface"], "wlan9mon")

    def test_replay_blocked_without_capture(self):
        eng = self.make_engine()
        eng.handle({"cmd": "authorize"})
        eng.handle({"cmd": "replay", "count": 5})
        self.assertEqual(eng.state["replay"]["frames"], 0)
        self.assertFalse(eng.capture.replay_active)
        self.assertFalse(eng.state["proof"]["confirmed"])

    def test_failed_injection_is_not_counted(self):
        req, _, _, _ = frames()
        feeds = [dot11.build_capture_buffer(req)]
        eng = self.make_engine(feeds=feeds, inject_ok=False)
        eng.handle({"cmd": "authorize"})
        eng.handle({"cmd": "monitor"})
        for buf in list(feeds):
            eng.feed(buf)
        eng.handle({"cmd": "replay", "count": 3})
        self.assertEqual(eng.state["replay"]["frames"], 0)
        self.assertEqual(eng.state["replay"]["write_errors"], 3)
        self.assertFalse(eng.state["proof"]["confirmed"])
        self.assertTrue(any("kernel" in r
                            for r in eng.state["proof"]["reasons"]))

    def test_failed_writes_never_confirm_even_with_response_and_pn_reuse(self):
        req, resp, before, after = frames()
        feeds = ([dot11.build_capture_buffer(req)] +
                 [dot11.build_capture_buffer(f) for f in before])
        eng = self.make_engine(feeds=feeds, inject_ok=False)
        eng.handle({"cmd": "authorize"})
        eng.handle({"cmd": "monitor"})
        for buf in list(feeds):
            eng.feed(buf)
        eng.handle({"cmd": "replay", "count": 3})
        eng.feed(dot11.build_capture_buffer(resp))
        for f in after:
            eng.feed(dot11.build_capture_buffer(f))
        eng.handle({"cmd": "verify"})
        self.assertFalse(eng.state["proof"]["confirmed"])

    def test_target_mismatch_blocks_replay(self):
        req, _, _, _ = frames()
        feeds = [dot11.build_capture_buffer(req)]
        eng = self.make_engine(feeds=feeds)
        eng.handle({"cmd": "authorize"})
        eng.handle({"cmd": "monitor"})
        for buf in feeds:
            eng.feed(buf)
        eng.state["target"]["bssid"] = "00:11:22:33:44:55"
        eng.handle({"cmd": "replay", "count": 3})
        self.assertEqual(eng.state["replay"]["frames"], 0)
        self.assertIn("blocked", " ".join(eng.state["logs"]))

    def test_clear_preserves_operator_count(self):
        eng = self.make_engine()
        eng.handle({"cmd": "authorize"})
        eng.handle({"cmd": "count", "value": 10})
        eng.handle({"cmd": "clear"})
        self.assertEqual(eng.state["replay"]["count"], 10)

    def test_target_change_clears_stale_proof(self):
        req, resp, before, after = frames()
        feeds = ([dot11.build_capture_buffer(req)] +
                 [dot11.build_capture_buffer(f) for f in before])
        eng = self.make_engine(feeds=feeds)
        eng.handle({"cmd": "authorize"})
        eng.handle({"cmd": "monitor"})
        for buf in list(feeds):
            eng.feed(buf)
        eng.handle({"cmd": "replay", "count": 3})
        eng.feed(dot11.build_capture_buffer(resp))
        for f in after:
            eng.feed(dot11.build_capture_buffer(f))
        eng.handle({"cmd": "verify"})
        self.assertTrue(eng.state["proof"]["confirmed"])
        eng.handle({"cmd": "target", "value": "00:11:22:33:44:55"})
        self.assertFalse(eng.state["proof"]["confirmed"])

    def test_malformed_command_line_does_not_kill_engine(self):
        eng = self.make_engine()
        eng.handle({"cmd": "authorize"})
        with open(eng.cmd_path, "w") as fh:
            fh.write("42\n")
        eng.drain_commands()
        self.assertTrue(eng.running)

    def test_infinite_numeric_commands_are_rejected(self):
        eng = self.make_engine()
        eng.handle({"cmd": "authorize"})
        with open(eng.cmd_path, "w") as fh:
            fh.write('{"cmd":"count","value":1e309}\n')
            fh.write('{"cmd":"replay","count":1e309}\n')
            fh.write('{"cmd":"sniff","seconds":1e309}\n')
        eng.drain_commands()
        self.assertTrue(eng.running)
        self.assertEqual(eng.state["replay"]["count"], 3)

    def test_iface_change_clears_stale_proof(self):
        req, resp, before, after = frames()
        feeds = ([dot11.build_capture_buffer(req)] +
                 [dot11.build_capture_buffer(f) for f in before])
        eng = self.make_engine(feeds=feeds)
        eng.handle({"cmd": "authorize"})
        eng.handle({"cmd": "monitor"})
        for buf in list(feeds):
            eng.feed(buf)
        eng.handle({"cmd": "replay", "count": 3})
        eng.feed(dot11.build_capture_buffer(resp))
        for f in after:
            eng.feed(dot11.build_capture_buffer(f))
        eng.handle({"cmd": "verify"})
        self.assertTrue(eng.state["proof"]["confirmed"])
        eng.handle({"cmd": "iface", "value": "wlan0mon"})
        self.assertFalse(eng.state["proof"]["confirmed"])
        self.assertEqual(eng.state["monitor"], "none")

    def test_end_to_end_proof_with_mock(self):
        req, resp, before, after = frames()
        feeds = ([dot11.build_capture_buffer(req)] +
                 [dot11.build_capture_buffer(f) for f in before])
        eng = self.make_engine(feeds=feeds)
        eng.handle({"cmd": "authorize"})
        eng.handle({"cmd": "monitor"})
        for buf in list(feeds):
            eng.feed(buf)
        eng.handle({"cmd": "replay", "count": 3})
        self.assertEqual(eng.state["replay"]["frames"], 3)
        self.assertTrue(all(x[8:] == req for x in eng.injector.injected))
        eng.feed(dot11.build_capture_buffer(resp))
        for f in after:
            eng.feed(dot11.build_capture_buffer(f))
        eng.handle({"cmd": "verify"})
        self.assertTrue(eng.state["proof"]["confirmed"])

    def test_no_monitor_is_honest(self):
        eng = engine.Engine(
            state_path=tempfile.mktemp(), cmd_path=tempfile.mktemp(),
            loot=tempfile.mktemp())
        eng.handle({"cmd": "authorize"})
        eng.handle({"cmd": "iface", "value": "wlan1mon-nope"})
        eng.handle({"cmd": "monitor"})
        self.assertEqual(eng.state["monitor"], "none")

    def test_selftest_subprocess(self):
        proc = subprocess.run([sys.executable, os.path.join(ROOT, "ftkrack.py"),
                               "selftest"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("selftest: PASS", proc.stdout)

    def test_capcheck_subprocess(self):
        proc = subprocess.run([sys.executable, os.path.join(ROOT, "ftkrack.py"),
                               "capcheck"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("capcheck: PASS", proc.stdout)


class UITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, os.path.join(ROOT, "ft"))
        import ui
        cls.ui = ui

    def test_headless_render_all_screens(self):
        pager = self.ui.FakePager()
        inst = self.ui.FtKrackUI(pager)
        inst.state = self.ui.sample_state()
        with pager:
            pager.init()
            for _ in range(len(self.ui.SCREENS)):
                inst.render()
                inst.screen_idx = (inst.screen_idx + 1) % len(self.ui.SCREENS)
        self.assertGreaterEqual(pager.frames, len(self.ui.SCREENS))

    def test_each_screen_renders_own_content(self):
        markers = {
            "INTRO": "FTKRACK // 802.11r FT KEY REINSTALL",
            "TARGET": "MONITOR INTERFACE",
            "CAPTURE": "FT REASSOCIATION CAPTURE",
            "REPLAY": "VERBATIM REASSOC REPLAY",
            "PROOF": "REINSTALLATION PROOF",
            "LOG": "FTKRACK ready",
        }
        for idx, screen in enumerate(self.ui.SCREENS):
            pager = self.ui.FakePager()
            inst = self.ui.FtKrackUI(pager)
            inst.state = self.ui.sample_state()
            inst.screen_idx = idx
            inst.render()
            self.assertTrue(
                any(markers[screen] in t for t in pager.texts),
                f"screen {screen} did not render its own content",
            )

    def test_unconfirmed_proof_is_not_green(self):
        pager = self.ui.FakePager()
        inst = self.ui.FtKrackUI(pager)
        st = self.ui.sample_state()
        st["proof"]["confirmed"] = False
        st["capture"]["captured"] = False
        inst.state = st
        inst.screen_idx = self.ui.SCREENS.index("PROOF")
        inst.render()
        self.assertTrue(any("UNCONFIRMED" in t for t in pager.texts))

    def test_real_pager_tuple_event_dispatches_button(self):
        """PAGERCTL returns (button, type, timestamp), not an object."""
        class OneShotPager(self.ui.FakePager):
            def __init__(self):
                super().__init__()
                self.sent = False

            def get_input_event(self):
                if not self.sent:
                    self.sent = True
                    return (self.BTN_A, 1, 1234)
                raise KeyboardInterrupt

        cmdfile = tempfile.mktemp()
        old = os.environ.get("FTKRACK_CMD")
        os.environ["FTKRACK_CMD"] = cmdfile
        try:
            inst = self.ui.FtKrackUI(OneShotPager())
            inst.state = {"authorized": False}
            try:
                inst.run()
            except KeyboardInterrupt:
                pass
            with open(cmdfile) as fh:
                self.assertIn('"authorize"', fh.read())
        finally:
            if old is None:
                os.environ.pop("FTKRACK_CMD", None)
            else:
                os.environ["FTKRACK_CMD"] = old
            if os.path.exists(cmdfile):
                os.remove(cmdfile)

    def test_fake_pager_accepts_three_element_events(self):
        pager = self.ui.FakePager()
        pager.events = [(pager.BTN_B, 1, 42)]
        ev = pager.get_input_event()
        self.assertEqual(ev.button, pager.BTN_B)
        self.assertEqual(ev.type, 1)

    def test_ui_commands_are_queued(self):
        cmdfile = tempfile.mktemp()
        old = os.environ.get("FTKRACK_CMD")
        os.environ["FTKRACK_CMD"] = cmdfile
        try:
            inst = self.ui.FtKrackUI(self.ui.FakePager())
            inst.state = {"authorized": False}
            inst.last_sent = 0
            inst.button(inst.p.BTN_A)
            inst.screen_idx = self.ui.SCREENS.index("REPLAY")
            inst.last_sent = 0
            inst.button(inst.p.BTN_A)
            with open(cmdfile) as fh:
                data = fh.read()
            self.assertIn('"authorize"', data)
            self.assertIn('"replay"', data)
        finally:
            if old is None:
                os.environ.pop("FTKRACK_CMD", None)
            else:
                os.environ["FTKRACK_CMD"] = old
            if os.path.exists(cmdfile):
                os.remove(cmdfile)


if __name__ == "__main__":
    unittest.main(verbosity=2)
