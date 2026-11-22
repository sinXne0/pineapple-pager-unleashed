"""Hardware-free test suite for ELRSJACK.

All radio interaction is mocked.  No Pager, no SX1262, no live ELRS link.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from elrs import capture, crack, crypto, engine, fhss, ota, radio  # noqa: E402


class CryptoTests(unittest.TestCase):
    def test_blank_phrase_is_unbound(self):
        self.assertEqual(crypto.uid_from_binding_phrase(""), bytes(6))

    def test_test_phrase_vector(self):
        self.assertEqual(crypto.uid_from_binding_phrase("test").hex(), "4f04fd822155")

    def test_md5_construction_is_exact(self):
        import hashlib
        expected = hashlib.md5(b'-DMY_BINDING_PHRASE="test"').digest()[:6]
        self.assertEqual(crypto.uid_from_binding_phrase("test"), expected)

    def test_unicode_phrase(self):
        uid = crypto.uid_from_binding_phrase("绿")
        self.assertEqual(len(uid), 6)
        self.assertNotEqual(uid, bytes(6))

    def test_crc_initializer(self):
        uid = bytes([0, 0, 0, 0, 0x21, 0x55])
        self.assertEqual(crypto.crc_initializer(uid), 0x2155 ^ 0x0400)

    def test_uid_seed(self):
        uid = bytes([0, 0, 0x2A, 0x7F, 0x11, 0x22])
        self.assertEqual(crypto.uid_seed(uid), 0x2A7F1126)

    def test_uid_is_bound(self):
        self.assertFalse(crypto.uid_is_bound(bytes(6)))
        self.assertTrue(crypto.uid_is_bound(bytes([0, 0, 0, 0, 1, 0])))

    def test_crc_tables_deterministic(self):
        a = crypto.crc_calc(b"\x02abcdef", 7, 0x1234, 14)
        b = crypto.crc_calc(b"\x02abcdef", 7, 0x1234, 14)
        self.assertEqual(a, b)


class FHSSTests(unittest.TestCase):
    def test_lcg_matches_source(self):
        rng = fhss.LCG(0)
        self.assertEqual(rng.rng(), 2531011 >> 16)

    def test_domain_frequencies(self):
        self.assertEqual(fhss.sync_frequency(fhss.DOMAINS["FCC915"]), 915500000)
        self.assertEqual(fhss.sync_frequency(fhss.DOMAINS["EU868"]), 866425000)

    def test_sequence_length(self):
        for dom in fhss.DOMAINS.values():
            seq = fhss.build_sequence(1234, dom)
            self.assertEqual(len(seq), dom.sequence_len)

    def test_sync_positions_are_fixed(self):
        dom = fhss.DOMAINS["FCC915"]
        seq = fhss.build_sequence(0xDEADBEEF, dom)
        for i in range(0, len(seq), dom.freq_count):
            self.assertEqual(seq[i], dom.sync_channel)

    def test_sequence_is_deterministic(self):
        a = fhss.build_sequence(0x2A7F1126, fhss.DOMAINS["FCC915"])
        b = fhss.build_sequence(0x2A7F1126, fhss.DOMAINS["FCC915"])
        self.assertEqual(a, b)

    def test_seed_top_bit_ambiguity(self):
        dom = fhss.DOMAINS["FCC915"]
        a = fhss.build_sequence(0x2A7F1126, dom)
        b = fhss.build_sequence(0xAA7F1126, dom)
        self.assertEqual(a, b)

    def test_channel_roundtrip(self):
        dom = fhss.DOMAINS["EU868"]
        for i in range(dom.freq_count):
            self.assertEqual(dom.channel_index(dom.channel_hz(i)), i)


class OTATests(unittest.TestCase):
    def test_sync_roundtrip_ota4(self):
        uid = crypto.uid_from_binding_phrase("test")
        pkt = ota.build_sync(uid, 20, packet_size=8)
        self.assertEqual(len(pkt), 8)
        parsed = ota.parse_sync(pkt)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.uid4, uid[4])
        self.assertEqual(parsed.uid5, uid[5])
        self.assertEqual(parsed.fhss_index, 20)

    def test_sync_roundtrip_ota8(self):
        uid = crypto.uid_from_binding_phrase("test")
        pkt = ota.build_sync(uid, 20, packet_size=13)
        parsed = ota.parse_sync(pkt)
        self.assertIsNotNone(parsed)
        self.assertEqual(len(pkt), 13)

    def test_corrupt_packet_rejected(self):
        uid = crypto.uid_from_binding_phrase("test")
        pkt = bytearray(ota.build_sync(uid, 20, packet_size=8))
        pkt[1] ^= 0xFF
        self.assertIsNone(ota.parse_sync(bytes(pkt)))

    def test_non_sync_type_rejected(self):
        uid = crypto.uid_from_binding_phrase("test")
        pkt = bytearray(ota.build_sync(uid, 20, packet_size=8))
        pkt[0] &= 0xFC
        self.assertIsNone(ota.parse_sync(bytes(pkt)))

    def test_wrong_length_rejected(self):
        self.assertIsNone(ota.parse_sync(b"\x02\x00\x00"))


class CaptureTests(unittest.TestCase):
    def make_capture(self, phrase="test", domain="FCC915"):
        uid = crypto.uid_from_binding_phrase(phrase)
        dom = fhss.DOMAINS[domain]
        return uid, dom, capture.CaptureEngine(domain)

    def test_feed_sync_packet(self):
        uid, dom, eng = self.make_capture()
        pkt = ota.build_sync(uid, dom.sync_channel, packet_size=8)
        sync = eng.feed_packet(pkt, fhss.sync_frequency(dom), -55, "100Hz")
        self.assertIsNotNone(sync)
        self.assertEqual(eng.valid_sync_packets, 1)
        self.assertEqual(sync.uid4, uid[4])
        self.assertEqual(sync.uid5, uid[5])

    def test_random_packet_ignored(self):
        _, dom, eng = self.make_capture()
        self.assertIsNone(eng.feed_packet(b"\x01\x02\x03\x04\x05\x06\x07\x08",
                                          fhss.sync_frequency(dom)))
        self.assertEqual(eng.valid_sync_packets, 0)

    def test_recover_uid_from_hop_timing(self):
        uid, dom, eng = self.make_capture()
        seq = fhss.build_sequence(crypto.uid_seed(uid), dom)
        si = dom.sync_channel
        ci = seq[(si + 1) % len(seq)]
        hz = dom.channel_hz(ci)
        offsets = [off for off in range(1, len(seq))
                   if seq[(si + off) % len(seq)] == ci][:6]
        eng.feed_packet(ota.build_sync(uid, si, packet_size=8),
                        fhss.sync_frequency(dom), -50, "100Hz")
        for off in offsets:
            eng.add_channel_sample(hz, uid[4], uid[5], si, off)
        result = eng.recover_uid()
        self.assertGreaterEqual(result.observations_used, 4)
        self.assertIn(uid[2:], [u[2:] for u in (result.candidate_uids or [])])

    def test_recover_without_sync_returns_none(self):
        _, _, eng = self.make_capture()
        result = eng.recover_uid()
        self.assertFalse(result.confirmed)
        self.assertIsNone(result.uid)


class CrackTests(unittest.TestCase):
    def test_crack_recovers_phrase(self):
        uid = crypto.uid_from_binding_phrase("test")
        result = crack.crack_uid_tail(uid[2:6], crack.load_default_wordlist())
        self.assertTrue(result.confirmed)
        self.assertEqual(result.phrase, "test")

    def test_crack_rejects_nonmatch(self):
        result = crack.crack_uid_tail(bytes([0xFF] * 4), crack.load_default_wordlist())
        self.assertFalse(result.confirmed)
        self.assertIsNone(result.phrase)

    def test_mutations(self):
        self.assertIn("abc", list(crack.mutations("ABC")))
        self.assertIn("abcdef", list(crack.mutations("ab cd ef")))


class EngineTests(unittest.TestCase):
    def test_authorize_gate(self):
        eng = engine.Engine(state_path="/tmp/eng_test_state.json",
                            cmd_path="/tmp/eng_test_cmd.jsonl",
                            loot="/tmp/eng_test_loot")
        eng.handle({"cmd": "domain", "value": "EU868"})
        self.assertEqual(eng.state["domain"], "FCC915")
        eng.handle({"cmd": "authorize"})
        eng.handle({"cmd": "domain", "value": "EU868"})
        self.assertEqual(eng.state["domain"], "EU868")

    def test_selftest_end_to_end(self):
        import subprocess
        proc = subprocess.run([sys.executable, os.path.join(ROOT, "elrsjack.py"),
                               "selftest"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("selftest: PASS", proc.stdout)

    def test_capcheck(self):
        import subprocess
        proc = subprocess.run([sys.executable, os.path.join(ROOT, "elrsjack.py"),
                               "capcheck"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_no_radio_is_honest(self):
        eng = engine.Engine(state_path="/tmp/eng_noradio_state.json",
                            cmd_path="/tmp/eng_noradio_cmd.jsonl",
                            loot="/tmp/eng_noradio_loot")
        eng.handle({"cmd": "authorize"})
        if radio.find_spidev() is None:
            eng.handle({"cmd": "capture", "seconds": 0.1})
            self.assertEqual(eng.state["radio"], "none")
            self.assertEqual(eng.capture.raw_packets, 0)


class UITests(unittest.TestCase):
    def test_headless_render_all_screens(self):
        sys.path.insert(0, os.path.join(ROOT, "elrs"))
        import ui
        pager = ui.FakePager()
        inst = ui.ElrsJackUI(pager)
        inst.state = ui.sample_state()
        with pager:
            pager.init()
            for _ in range(len(ui.SCREENS)):
                inst.render()
                inst.screen_idx = (inst.screen_idx + 1) % len(ui.SCREENS)
        self.assertGreaterEqual(pager.frames, len(ui.SCREENS))

    def test_each_screen_renders_its_own_content(self):
        markers = {
            "INTRO": "ELRSJACK // ELRS 900M LINK RECON",
            "RADIO": "REGULATORY DOMAIN",
            "SCAN": "SYNC PACKET CAPTURE",
            "TRACK": "HOP TIMING CAPTURE",
            "UID": "FHSS SEED RECOVERY",
            "PROBE": "AUTHORIZED BENCH LINK PROBE",
            "LOG": "ELRSJACK ready",
        }
        sys.path.insert(0, os.path.join(ROOT, "elrs"))
        import ui
        for idx, screen in enumerate(ui.SCREENS):
            pager = ui.FakePager()
            inst = ui.ElrsJackUI(pager)
            inst.state = ui.sample_state()
            inst.screen_idx = idx
            inst.render()
            self.assertTrue(
                any(markers[screen] in text for text in pager.texts),
                f"screen {screen} did not render its own content",
            )

    def test_authorize_button(self):
        sys.path.insert(0, os.path.join(ROOT, "elrs"))
        import ui
        cmdfile = tempfile.mktemp()
        old = os.environ.get("ELRSJACK_CMD")
        os.environ["ELRSJACK_CMD"] = cmdfile
        try:
            inst = ui.ElrsJackUI(ui.FakePager())
            inst.state = {"authorized": False}
            inst.last_sent = 0
            inst.button(inst.p.BTN_A)
            with open(cmdfile) as fh:
                self.assertIn("authorize", fh.read())
        finally:
            if old is None:
                os.environ.pop("ELRSJACK_CMD", None)
            else:
                os.environ["ELRSJACK_CMD"] = old
            if os.path.exists(cmdfile):
                os.remove(cmdfile)


if __name__ == "__main__":
    unittest.main(verbosity=2)
