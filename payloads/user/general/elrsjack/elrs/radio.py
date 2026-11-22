"""SX1262 raw LoRa access through the Glytch Mesh Mod's ch341 SPI bridge.

The Pager's Meshtastic service owns the SX1262 while it is running.  ELRSJACK
stops meshtasticd, opens the ch341 spidev node, and drives the radio directly.
Only the SPI bus is required -- CS is handled by spidev, and the busy/IRQ
lines are polled through SX1262 status registers.  No cross-compiled helper,
no third-party Python packages.

HONESTY: this module never claims a packet was received unless the SX1262
reported RX_DONE and the OTA layer validated the ELRS CRC.  If no spidev node
is present, or the SX1262 does not answer GetStatus, capability is 'none'
and the UI shows NO RADIO.  MockRadio exists only for the test suite.
"""

from __future__ import annotations

import ctypes
import glob
import fcntl
import os
import struct
import time
from typing import Optional

# SX1262 opcodes (RadioLib SX126x_commands.h)
CMD_GET_STATUS = 0xC0
CMD_SET_STANDBY = 0x80
CMD_SET_FS = 0xC1
CMD_SET_RX = 0x82
CMD_SET_TX = 0x83
CMD_SET_RF_FREQUENCY = 0x86
CMD_SET_PACKET_TYPE = 0x8A
CMD_SET_MODULATION_PARAMS = 0x8B
CMD_SET_PACKET_PARAMS = 0x8C
CMD_SET_TX_PARAMS = 0x8E
CMD_SET_BUFFER_BASE_ADDRESS = 0x8F
CMD_WRITE_REGISTER = 0x0D
CMD_READ_REGISTER = 0x1D
CMD_WRITE_BUFFER = 0x0E
CMD_READ_BUFFER = 0x1E
CMD_GET_IRQ_STATUS = 0x12
CMD_CLEAR_IRQ_STATUS = 0x02
CMD_GET_RX_BUFFER_STATUS = 0x13
CMD_GET_PACKET_STATUS = 0x14
CMD_GET_RSSI_INST = 0x15
CMD_SET_DIO2_AS_RF_SWITCH_CTRL = 0x9D
CMD_SET_LORA_SYMB_NUM_TIMEOUT = 0xA0

REG_LORA_SYNC_MSB = 0x0740
REG_LORA_SYNC_LSB = 0x0741

IRQ_RX_DONE = 1 << 6
IRQ_CRC_ERROR = 1 << 11
IRQ_RX_TIMEOUT = 1 << 14

SPI_IOC_MAGIC = 0x6B
SPI_IOC_MESSAGE_1 = (3 << 30) | (32 << 16) | (SPI_IOC_MAGIC << 8) | 1

# SX1262 XTAL frequency for FREQ_HZ_TO_REG_VAL: 32 MHz / 2**19 = 61.03515625 Hz
XTAL_STEP_HZ = 32_000_000.0 / (1 << 19)

# ELRS 900M air rates from ExpressLRS src/src/common.cpp (SX127x table).
# (name, sf, bw_khz, cr_denom, sync_candidates)
ELRS_RATES = {
    "200Hz": (6, 500, 7, (0x1212, 0x1424, 0x3444, 0x0000)),
    "100Hz": (7, 500, 7, (0x1212, 0x1424, 0x3444, 0x0000)),
    "50Hz":  (8, 500, 7, (0x1212, 0x1424, 0x3444, 0x0000)),
    "25Hz":  (9, 500, 7, (0x1212, 0x1424, 0x3444, 0x0000)),
}


class RadioError(Exception):
    pass


def find_spidev() -> Optional[str]:
    """Locate a ch341-backed spidev node.  Sorted for deterministic selection."""
    nodes = sorted(glob.glob("/dev/spidev*"))
    return nodes[0] if nodes else None


class SpiRadio:
    """Minimal SX1262 driver over Linux spidev (pure stdlib)."""

    def __init__(self, path: str | None = None, speed_hz: int = 2_000_000):
        self.path = path or find_spidev()
        if not self.path:
            raise RadioError("no /dev/spidev node (is the ch341 SPI driver loaded?)")
        self.speed_hz = speed_hz
        self.fd = os.open(self.path, os.O_RDWR)
        self._sync_word = None
        self._rate = None
        self._frequency_hz = None

    def close(self):
        try:
            os.close(self.fd)
        except OSError:
            pass
        self.fd = -1

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def transfer(self, tx: bytes, rx_len: int = 0) -> bytes:
        """One half-duplex SPI transfer via SPI_IOC_MESSAGE(1)."""
        if self.fd < 0:
            raise RadioError("SPI device closed")
        length = max(len(tx), rx_len)
        tx_buf = bytearray(length)
        tx_buf[:len(tx)] = tx
        rx_buf = bytearray(rx_len)
        tx_addr = ctypes.addressof(ctypes.c_char.from_buffer(tx_buf))
        rx_addr = ctypes.addressof(ctypes.c_char.from_buffer(rx_buf)) if rx_len else 0
        pkt = struct.pack("=QQIIHBBBBH", tx_addr, rx_addr, length,
                          self.speed_hz, 0, 8, 0, 0, 0, 0)
        fcntl.ioctl(self.fd, SPI_IOC_MESSAGE_1, pkt, True)
        return bytes(rx_buf)

    def command(self, opcode: int, data: bytes = b"", rx_len: int = 1) -> bytes:
        return self.transfer(bytes([opcode]) + data, rx_len=1 + len(data) + rx_len)[1 + len(data):]

    def write_register(self, addr: int, data: bytes):
        hi, lo = (addr >> 8) & 0xFF, addr & 0xFF
        self.command(CMD_WRITE_REGISTER, bytes([hi, lo]) + data, rx_len=1)

    def read_register(self, addr: int, length: int = 1) -> bytes:
        hi, lo = (addr >> 8) & 0xFF, addr & 0xFF
        raw = self.transfer(bytes([CMD_READ_REGISTER, hi, lo]) + b"\x00" * length,
                            rx_len=3 + length)
        return raw[3:]

    def get_status(self) -> int:
        return self.command(CMD_GET_STATUS, rx_len=1)[0]

    def probe(self) -> bool:
        """Return True only if the SX1262 answers GetStatus on this SPI node."""
        try:
            status = self.get_status()
            # Status byte: bits 4-2 are the command status; 0b010 = RFU/idle is
            # unusual but alive.  Any non-0xFF response means a chip answered.
            return status != 0xFF and status != 0x00
        except (OSError, RadioError):
            return False

    def set_standby(self):
        self.command(CMD_SET_STANDBY, b"\x00", rx_len=1)

    def set_frequency(self, hz: int):
        reg = int(round(hz / XTAL_STEP_HZ)) & 0xFFFFFFFF
        self.command(CMD_SET_RF_FREQUENCY, struct.pack(">I", reg), rx_len=1)
        self._frequency_hz = hz

    def set_sync_word(self, word: int):
        self.write_register(REG_LORA_SYNC_MSB, bytes([(word >> 8) & 0xFF]))
        self.write_register(REG_LORA_SYNC_LSB, bytes([word & 0xFF]))
        self._sync_word = word

    def configure(self, rate: str, frequency_hz: int, sync_word: int):
        """Configure LoRa modem for one ELRS 900M air rate."""
        if rate not in ELRS_RATES:
            raise RadioError("unknown rate: " + rate)
        sf, bw_khz, cr_denom, _ = ELRS_RATES[rate]
        self.set_standby()
        self.command(CMD_SET_PACKET_TYPE, b"\x01", rx_len=1)  # LoRa
        # SetModulationParams: SF, BW, CR, LDRO
        bw_code = {125: 0x00, 250: 0x01, 500: 0x02}.get(bw_khz, 0x02)
        cr_code = {5: 0x01, 6: 0x02, 7: 0x03, 8: 0x04}.get(cr_denom, 0x03)
        self.command(CMD_SET_MODULATION_PARAMS,
                     bytes([sf, bw_code, cr_code, 0x00]), rx_len=1)
        # SetPacketParams: preamble=8, implicit header off, payload len, CRC off
        self.command(CMD_SET_PACKET_PARAMS,
                     bytes([0x00, 0x08, 0x00, 8, 0x00, 0x00]), rx_len=1)
        self.command(CMD_SET_BUFFER_BASE_ADDRESS, b"\x00\x00", rx_len=1)
        self.set_sync_word(sync_word)
        self.set_frequency(frequency_hz)
        self.command(CMD_SET_DIO2_AS_RF_SWITCH_CTRL, b"\x01", rx_len=1)

    def start_rx(self):
        self.command(CMD_CLEAR_IRQ_STATUS, b"\xFF\xFF", rx_len=1)
        self.command(CMD_SET_RX, b"\xFF\xFF\xFF", rx_len=1)  # continuous

    def read_packet(self, timeout_s: float = 0.5) -> tuple[bytes, int] | None:
        """Poll for a complete packet.  Returns (payload, rssi_dbm) or None."""
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            irq = struct.unpack("<H", self.command(CMD_GET_IRQ_STATUS, b"\xFF\xFF", rx_len=2))[0]
            if irq & IRQ_RX_DONE:
                status = self.command(CMD_GET_RX_BUFFER_STATUS, b"\x00", rx_len=2)
                length = status[0]
                if length == 0 or length > 255:
                    self.command(CMD_CLEAR_IRQ_STATUS, b"\xFF\xFF", rx_len=1)
                    return None
                payload = self.command(CMD_READ_BUFFER, b"\x00" + bytes([length]),
                                       rx_len=length)
                rssi_raw = self.command(CMD_GET_RSSI_INST, b"\x00", rx_len=1)[0]
                self.command(CMD_CLEAR_IRQ_STATUS, b"\xFF\xFF", rx_len=1)
                return bytes(payload), -int(rssi_raw) // 2
            if irq & (IRQ_CRC_ERROR | IRQ_RX_TIMEOUT):
                self.command(CMD_CLEAR_IRQ_STATUS, b"\xFF\xFF", rx_len=1)
            time.sleep(0.005)
        return None


class MockRadio:
    """Deterministic radio for hardware-free tests.  Not used on the Pager."""

    def __init__(self, packets=None):
        self.packets = list(packets or [])
        self.config = None
        self.capability = "mock"

    def probe(self):
        return True

    def configure(self, rate, frequency_hz, sync_word):
        self.config = (rate, frequency_hz, sync_word)

    def start_rx(self):
        pass

    def read_packet(self, timeout_s=0.5):
        if not self.packets:
            return None
        pkt = self.packets.pop(0)
        return (pkt[0], pkt[1]) if isinstance(pkt, tuple) else (pkt, -60)

    def close(self):
        pass
