# ECHOFIELD

**Passive-radar console for the WiFi Pineapple Pager and HackRF.**

ECHOFIELD turns an ordinary FM broadcast into a radar illuminator. One
receiver watches the transmitter directly (the reference channel) while a
second watches the area of interest (the surveillance channel). Correlating
them produces a range/Doppler map: moving aircraft and vehicles show up as
peaks even though ECHOFIELD transmits nothing itself.

The Pager runs the console. The HackRF side can be two synchronized HackRFs,
a recorded IQ pair, or a synthetic source for testing the UI without radios.

> **Lawful use only.** Passive receive needs no broadcast license. Any mode
> that transmits requires licensed hardware, appropriate band privileges, and
> written authorization. Do not point this at aviation or emergency systems.

```
SCOPE     ▸ live range/Doppler map, 0-100 km by -250..+250 Hz
CONTACTS  ▸ tracked peaks: range, radial velocity, SNR
SETUP     ▸ mode, frequency, gain, sample rate
LOG       ▸ capture and error history
```

Buttons:

- **Left / Right** — change screen
- **Up / Down** — move the selection
- **A** — start/stop capture, or acknowledge a contact
- **B** — back to SCOPE

---

## Modes

| Mode | What it does | Hardware |
| --- | --- | --- |
| `sim` | Synthetic moving contacts for UI testing | none |
| `file` | Correlate two recorded IQ files | any SDR that produced the files |
| `hackrf` | Capture two coherent channels, then correlate | two HackRFs sharing a 10 MHz reference |

A single HackRF is half-duplex and cannot provide both channels at once.
Real passive radar needs two coherent receivers, or an external capture
helper that provides both files.

### External capture helper

Set `ECHOFIELD_CAPTURE` to a command that accepts:

```text
<command> <freq_hz> <sample_rate> <samples> <ref_path> <surv_path>
```

The command must write two IQ files. Otherwise ECHOFIELD calls
`hackrf_transfer` twice using:

- `ECHOFIELD_HACKRF_REF` — serial number of the reference HackRF
- `ECHOFIELD_HACKRF_SURV` — serial number of the surveillance HackRF

---

## Install

Copy the folder to:

```text
/root/payloads/user/reconnaissance/echofield/
```

Launch from **Payloads ▸ user ▸ reconnaissance ▸ ECHOFIELD**. `payload.sh`
self-locates, so the parent directory name can be changed.

Dependencies:

- `python3-light` (required)
- bundled `lib/libpagerctl.so` (required for the Pager display)
- `hackrf-transfer` (only for `hackrf` mode)
- `numpy` (optional; greatly speeds up CAF processing)

Environment overrides:

```text
ECHOFIELD_MODE       sim | file | hackrf
ECHOFIELD_FREQ       FM frequency in MHz, default 100.1
ECHOFIELD_RATE       sample rate in Hz, default 2000000
ECHOFIELD_GAIN       HackRF IF gain, default 24
ECHOFIELD_INTERVAL   seconds between frames, default 1.5
ECHOFIELD_REF        reference IQ path for file mode
ECHOFIELD_SURV       surveillance IQ path for file mode
ECHOFIELD_CAPTURE    external capture command
ECHOFIELD_STATE      state JSON path
ECHOFIELD_CMD        command JSONL path
ECHOFIELD_LOOT       loot directory
```

---

## How it works

1. A strong FM transmitter is the illuminator. The reference antenna points
   at it; the surveillance antenna points at the search area.
2. Both receivers sample the same band coherently.
3. For each Doppler bin, ECHOFIELD mixes the surveillance signal and
   cross-correlates it with the reference signal.
4. Peaks in the resulting cross-ambiguity surface give bistatic range and
   radial velocity.
5. Contacts are tracked between frames and stored in loot.

With a 2 MHz sample rate, one range bin is about 75 m. Real-world
range resolution is dominated by the FM station's bandwidth and multipath.

---

## Tests

```text
python3 -m unittest discover -s tests -v
```

No radio, no Pager and no third-party modules are required for the test
suite. `numpy` is used automatically when present.

---

## Loot

```text
/root/loot/echofield/contacts.jsonl    timestamped contacts
/root/loot/echofield/echofield.log     engine/UI log
```

---

## Credits

ECHOFIELD's UI and engine are original. The Pager display library is the
firmware's own `libpagerctl.so`, shipped unmodified with a ctypes wrapper from
the Pager payload examples. The passive-radar technique is a well-known
bistatic radar method; this payload is a Pager-native implementation.
