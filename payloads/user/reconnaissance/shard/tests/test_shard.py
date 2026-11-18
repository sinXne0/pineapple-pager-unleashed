import json
import os
import struct
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from sd import discovery, engine, frames, inject  # noqa: E402
from sd.ui import ShardUI, FakePager, sample_state, send_cmd  # noqa: E402


class FrameTests(unittest.TestCase):
    def test_mac_parse_format(self):
        self.assertEqual(frames.mac_to_str("aa:bb:cc:dd:ee:ff"),
                         "aa:bb:cc:dd:ee:ff")
        self.assertEqual(frames.mac_to_str("AA-BB-CC-DD-EE-FF"),
                         "aa:bb:cc:dd:ee:ff")
        self.assertEqual(frames.mac_to_str(bytes.fromhex("aabbccddeeff")),
                         "aa:bb:cc:dd:ee:ff")

    def test_mac_rejects_bad(self):
        with self.assertRaises(ValueError):
            frames.mac_to_bytes("aa:bb:cc")

    def test_ip_roundtrip(self):
        self.assertEqual(frames.ip_to_str(frames.ip_to_bytes("192.168.1.1")),
                         "192.168.1.1")
        with self.assertRaises(ValueError):
            frames.ip_to_bytes("999.1.1.1")

    def test_checksum_known(self):
        # checksum of a header of all zeroes is 0xffff
        self.assertEqual(frames.checksum(b"\x00" * 20), 0xFFFF)

    def test_radiotap_header(self):
        rt = frames.build_radiotap(rate=0x02)
        version, pad, length, present = struct.unpack("<BBHI", rt[:8])
        self.assertEqual(version, 0)
        self.assertEqual(pad, 0)
        self.assertEqual(length, len(rt))
        self.assertTrue(present & (1 << frames.RT_FLAGS))
        self.assertTrue(present & (1 << frames.RT_RATE))
        self.assertTrue(present & (1 << frames.RT_TX_FLAGS))
        self.assertEqual(rt[8], frames.RT_F_FCS)
        self.assertEqual(rt[9], 0x02)

    def test_radiotap_with_channel(self):
        rt = frames.build_radiotap(channel=2437, power=20)
        length = struct.unpack("<H", rt[2:4])[0]
        self.assertEqual(length, len(rt))
        present = struct.unpack("<I", rt[4:8])[0]
        self.assertTrue(present & (1 << frames.RT_CHANNEL))
        self.assertIn(struct.pack("<H", 2437), rt)

    def test_frame_control_qos_fromds(self):
        fc = frames.frame_control(ftype=2, subtype=8, from_ds=1)
        value = struct.unpack("<H", fc)[0]
        self.assertEqual(value & 0x3, 0)               # version
        self.assertEqual((value >> 2) & 0x3, 2)        # data
        self.assertEqual((value >> 4) & 0xf, 8)        # QoS
        self.assertTrue(value & (1 << 9))              # FromDS

    def test_deauth_frame(self):
        f = frames.build_deauth("00:11:22:33:44:55", "aa:bb:cc:dd:ee:01")
        self.assertGreater(len(f), 24)
        self.assertEqual(f[4:10], bytes.fromhex("aabbccddee01"))  # RA = target
        self.assertEqual(f[10:16], bytes.fromhex("001122334455"))  # TA = BSSID

    def test_qos_amsdu_flag(self):
        f = frames.build_qos_data("aa:bb:cc:dd:ee:01", "00:11:22:33:44:55",
                                  "00:11:22:33:44:55", b"payload", amsdu=True)
        qos = struct.unpack("<H", f[24:26])[0]
        self.assertTrue(qos & 0x80)

    def test_amsdu_payload_padding_and_llc(self):
        p = frames.build_amsdu_payload("aa:bb:cc:dd:ee:01",
                                       "00:11:22:33:44:55", b"abc")
        self.assertEqual(len(p) % 4, 0)
        self.assertEqual(p[:6], bytes.fromhex("aabbccddee01"))  # DA = client
        self.assertEqual(p[6:12], bytes.fromhex("001122334455"))  # SA = BSSID
        self.assertEqual(p[14:22], frames.LLC_SNAP_IPV4)
        # Length field is at bytes 12..14 (after 6+6 DA/SA)
        length = struct.unpack(">H", p[12:14])[0]
        self.assertEqual(length, len(frames.LLC_SNAP_IPV4) + 3)

    def test_icmp_echo(self):
        pkt = frames.build_icmp_echo("192.168.1.1", "192.168.1.100",
                                     ident=0x1234, seq=1, payload=b"SHARD")
        self.assertEqual(pkt[0] >> 4, 4)
        self.assertEqual(pkt[9], 1)  # ICMP
        self.assertEqual(pkt[12:16], bytes([192, 168, 1, 1]))
        self.assertEqual(pkt[16:20], bytes([192, 168, 1, 100]))
        self.assertEqual(pkt[20], 8)  # echo request

    def test_dns_response(self):
        pkt = frames.build_dns_response_response(
            "192.168.1.1", "192.168.1.100", "canary.local", "172.16.52.1",
            transaction_id=0xABCD)
        self.assertEqual(pkt[9], 17)  # UDP
        self.assertIn(bytes([172, 16, 52, 1]), pkt)

    def test_full_injection_frame(self):
        frame = frames.build_amsdu_injection(
            "aa:bb:cc:dd:ee:01", "00:11:22:33:44:55",
            frames.build_icmp_echo("192.168.1.1", "192.168.1.100"))
        # radiotap length field describes only the radiotap header, not the frame
        self.assertEqual(struct.unpack("<H", frame[2:4])[0], 12)
        self.assertGreater(len(frame), 50)


class DiscoveryTests(unittest.TestCase):
    def test_is_injectable_2g(self):
        ok, reason = discovery.is_injectable_target({"channel": 6})
        self.assertTrue(ok, reason)

    def test_is_injectable_non_dfs_5g(self):
        ok, reason = discovery.is_injectable_target({"channel": 36})
        self.assertTrue(ok, reason)

    def test_dfs_blocked(self):
        for ch in (52, 64, 100, 144):
            ok, reason = discovery.is_injectable_target({"channel": ch})
            self.assertFalse(ok, "%s should be blocked" % ch)
            self.assertIn("DFS", reason)

    def test_6g_blocked(self):
        ok, reason = discovery.is_injectable_target({"channel": 1, "security": "WPA3"})
        self.assertFalse(ok)
        self.assertIn("WPA3", reason)

    def test_sample_targets(self):
        targets = discovery.sample_targets()
        self.assertGreaterEqual(len(targets), 3)
        self.assertTrue(any(t.get("injectable") for t in [
            dict(t, injectable=discovery.is_injectable_target(t)[0]) for t in targets]))


class InjectorTests(unittest.TestCase):
    def test_probe_raw_missing_iface(self):
        result = inject.probe_raw("shard-does-not-exist")
        self.assertFalse(result["exists"])
        self.assertFalse(result["os_ok"])
        self.assertTrue(result["error"])

    def test_capture_no_tcpdump(self):
        # Capture should never crash even with odd parameters.
        lines, err = inject.capture_response("shard-no-iface", duration=0.1)
        self.assertIsInstance(lines, list)
        self.assertIsInstance(err, str)


class EngineTests(unittest.TestCase):
    def make_engine(self, sim=True):
        d = tempfile.mkdtemp()
        return engine.Engine(os.path.join(d, "state.json"),
                             os.path.join(d, "cmd.jsonl"),
                             os.path.join(d, "loot"), sim=sim)

    def test_default_state(self):
        e = self.make_engine()
        self.assertEqual(e.state["app"], "SHARD")
        self.assertFalse(e.state["authorized"])

    def test_authorization_gate_discover(self):
        e = self.make_engine()
        e.handle({"cmd": "discover"})
        self.assertEqual(e.state["error"], "authorization required first")
        self.assertEqual(e.state["targets"], [])

    def test_sim_full_flow(self):
        e = self.make_engine()
        e.handle({"cmd": "authorize"})
        e.handle({"cmd": "discover"})
        self.assertGreater(len(e.state["targets"]), 0)
        e.handle({"cmd": "select", "index": 0})
        e.handle({"cmd": "probe"})
        self.assertTrue(e.state["probe"]["os_ok"])
        e.handle({"cmd": "inject"})
        self.assertEqual(e.state["inject_count"], 1)
        e.handle({"cmd": "verify"})
        self.assertTrue(e.state["verified"])
        self.assertEqual(e.state["phase"], "done")

    def test_blocked_target_cannot_inject(self):
        e = self.make_engine()
        e.handle({"cmd": "authorize"})
        e.state["selected"] = {"bssid": "00:11:22:33:44:55",
                               "client": "aa:bb:cc:dd:ee:01", "channel": 100}
        e.handle({"cmd": "inject"})
        self.assertEqual(e.state["inject_count"], 0)
        self.assertIn("blocked", e.state["error"])

    def test_attack_modes(self):
        e = self.make_engine()
        for mode in ("dns", "icmp", "amsdu"):
            e.handle({"cmd": "attack", "mode": mode})
            self.assertEqual(e.state["attack"], mode)

    def test_state_file_written(self):
        e = self.make_engine()
        e.handle({"cmd": "authorize"})
        e.handle({"cmd": "discover"})
        e.tick()
        self.assertTrue(os.path.exists(e.state_path))
        with open(e.state_path) as fh:
            s = json.load(fh)
        self.assertEqual(s["app"], "SHARD")

    def test_selftest_entrypoint(self):
        import subprocess
        out = subprocess.check_output(
            [sys.executable, os.path.join(ROOT, "shard.py"), "selftest"],
            text=True, env=dict(os.environ, SHARD_SIM="1"))
        self.assertIn("injected=1", out)
        self.assertIn("verified=True", out)


class UITests(unittest.TestCase):
    @staticmethod
    def click(ui, btn):
        ui.last_sent = 0.0
        ui.button(btn)

    def test_render_all_screens(self):
        p = FakePager()
        with p:
            ui = ShardUI(p)
            ui.state = sample_state()
            for i in range(len(__import__("sd.ui", fromlist=["SCREENS"]).SCREENS)):
                ui.screen_idx = i
                ui.render()
        self.assertGreater(p.frames, 0)

    def test_screen_wrap(self):
        p = FakePager()
        ui = ShardUI(p)
        self.click(ui, p.BTN_LEFT)
        self.assertEqual(ui.screen, "LOG")
        self.click(ui, p.BTN_RIGHT)
        self.assertEqual(ui.screen, "INTRO")

    def test_authorize_button(self):
        with tempfile.TemporaryDirectory() as d:
            cmdpath = os.path.join(d, "cmd.jsonl")
            os.environ["SHARD_CMD"] = cmdpath
            p = FakePager()
            ui = ShardUI(p)
            ui.state = {"authorized": False, "phase": "idle"}
            self.click(ui, p.BTN_A)
            with open(cmdpath) as fh:
                self.assertIn("authorize", fh.read())
            os.environ.pop("SHARD_CMD", None)

    def test_send_cmd_jsonl(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "cmd.jsonl")
            send_cmd({"cmd": "probe"}, path)
            with open(path) as fh:
                self.assertEqual(json.loads(fh.read().strip()), {"cmd": "probe"})


class LauncherTests(unittest.TestCase):
    def test_payload_header(self):
        with open(os.path.join(ROOT, "payload.sh")) as fh:
            text = fh.read()
        self.assertTrue(text.startswith("#!/bin/bash"))
        self.assertIn("# Title: SHARD", text)
        self.assertIn("AUTHORIZED TESTING ONLY", text)
        self.assertIn("wlan1mon", text)


if __name__ == "__main__":
    unittest.main()
