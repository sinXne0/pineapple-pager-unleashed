import json
import os
import struct
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from ef import engine, radar  # noqa: E402
from ef.ui import EchoFieldUI, FakePager, sample_state, send_cmd  # noqa: E402


class RadarTests(unittest.TestCase):
    def test_range_resolution(self):
        self.assertAlmostEqual(radar.range_resolution_km(2000000), 0.0749486, places=5)

    def test_lag_roundtrip(self):
        lag = radar.range_to_lag(50.0, 2000000)
        self.assertAlmostEqual(radar.lag_to_range_km(lag, 2000000), 50.0, delta=0.1)

    def test_sim_frame_shape_and_normalization(self):
        m = radar.simulate_frame(1.0, rows=18, cols=24)
        self.assertEqual(len(m), 18)
        self.assertTrue(all(len(row) == 24 for row in m))
        flat = [v for row in m for v in row]
        self.assertLessEqual(min(flat), 0.0)
        self.assertGreater(max(flat), 0.8)

    def test_find_peaks(self):
        m = [[0.0] * 9 for _ in range(9)]
        m[4][5] = 1.0
        peaks = radar.find_peaks(m, min_snr=0.5, max_peaks=3)
        self.assertTrue(peaks)
        self.assertEqual(peaks[0][:2], (4, 5))

    def test_sim_contacts(self):
        cs = radar.simulate_contacts(2.0, sample_rate_hz=2000000, rows=18, cols=24)
        self.assertGreaterEqual(len(cs), 2)
        for c in cs:
            self.assertIn("range_km", c)
            self.assertIn("velocity_ms", c)
            self.assertGreaterEqual(c["range_km"], 0)

    def test_read_iq_cs8(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(struct.pack("<4b", 10, -10, 20, -20))
            p = fh.name
        try:
            vals = radar.read_iq(p, "cs8")
            self.assertEqual(vals, [complex(10, -10) / 128, complex(20, -20) / 128])
        finally:
            os.unlink(p)

    def test_caf_slow_small(self):
        ref = [complex(1 if i % 8 < 4 else -1, 0) for i in range(128)]
        surv = ref[:]
        m = radar.caf_slow(ref, surv, 2000000, [-100, 0, 100], 16, stride=2)
        self.assertTrue(m)
        self.assertEqual(len(m[0]), 3)


class EngineTests(unittest.TestCase):
    def make_engine(self):
        d = tempfile.mkdtemp()
        return engine.Engine(os.path.join(d, "state.json"),
                             os.path.join(d, "cmd.jsonl"),
                             os.path.join(d, "loot"))

    def test_default_state(self):
        e = self.make_engine()
        self.assertEqual(e.state["app"], "ECHOFIELD")
        self.assertEqual(e.state["mode"], "sim")

    def test_start_stop_commands(self):
        e = self.make_engine()
        e.handle({"cmd": "start"})
        self.assertTrue(e.state["running"])
        e.handle({"cmd": "stop"})
        self.assertFalse(e.state["running"])

    def test_mode_and_freq(self):
        e = self.make_engine()
        e.handle({"cmd": "mode", "mode": "file"})
        e.handle({"cmd": "freq", "mhz": 99.5})
        self.assertEqual(e.state["mode"], "file")
        self.assertEqual(e.state["station"], "FM 99.5")

    def test_ack_removes_contact(self):
        e = self.make_engine()
        e.state["contacts"] = [{"id": "E01"}, {"id": "E02"}]
        e.handle({"cmd": "ack", "id": "E01"})
        self.assertEqual([c["id"] for c in e.state["contacts"]], ["E02"])

    def test_sim_frame_updates_state(self):
        e = self.make_engine()
        e.handle({"cmd": "start"})
        e.tick()
        self.assertTrue(os.path.exists(e.state_path))
        with open(e.state_path) as fh:
            s = json.load(fh)
        self.assertTrue(s["running"])
        self.assertTrue(s["caf"])
        self.assertGreater(len(s["contacts"]), 0)

    def test_error_mode_stops_cleanly(self):
        e = self.make_engine()
        e.state["mode"] = "bogus"
        e.handle({"cmd": "start"})
        e.tick()
        self.assertFalse(e.state["running"])
        self.assertTrue(e.state["error"])


class UITests(unittest.TestCase):
    @staticmethod
    def click(ui, btn):
        ui.last_sent = 0.0
        ui.button(btn)

    def test_render_all_screens(self):
        p = FakePager()
        with p:
            ui = EchoFieldUI(p)
            ui.state = sample_state()
            for i in range(4):
                ui.screen_idx = i
                ui.render()
        self.assertGreater(p.frames, 0)

    def test_screen_wrap(self):
        p = FakePager()
        ui = EchoFieldUI(p)
        self.click(ui, p.BTN_LEFT)
        self.assertEqual(ui.screen, "LOG")
        self.click(ui, p.BTN_RIGHT)
        self.assertEqual(ui.screen, "SCOPE")

    def test_contact_selection(self):
        p = FakePager()
        ui = EchoFieldUI(p)
        ui.screen_idx = 1
        ui.state = sample_state()
        self.click(ui, p.BTN_DOWN)
        self.assertEqual(ui.sel, 1)
        self.click(ui, p.BTN_UP)
        self.assertEqual(ui.sel, 0)

    def test_send_cmd_jsonl(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "cmd.jsonl")
            send_cmd({"cmd": "start"}, p)
            with open(p) as fh:
                self.assertEqual(json.loads(fh.read().strip()), {"cmd": "start"})


class LauncherTests(unittest.TestCase):
    def test_payload_header(self):
        with open(os.path.join(ROOT, "payload.sh")) as fh:
            text = fh.read()
        self.assertTrue(text.startswith("#!/bin/bash"))
        self.assertIn("# Title: ECHOFIELD", text)
        self.assertIn("ECHOFIELD_MODE", text)

    def test_entrypoint_selftest(self):
        import subprocess
        out = subprocess.check_output([sys.executable, os.path.join(ROOT, "echofield.py"),
                                       "selftest"], text=True)
        self.assertIn("matrix=", out)


if __name__ == "__main__":
    unittest.main()
