#!/usr/bin/env python3
"""Small CAF/radar helpers used by ECHOFIELD.

The full passive-radar math is deliberately kept in one module so the Pager UI
never has to know where the samples came from.  Three sources are supported:

* ``sim``     - synthetic contacts, no hardware
* ``file``    - two recorded IQ files (reference + surveillance)
* ``hackrf``  - two synchronized HackRF captures, delegated to ef.hackrf

The implementation prefers numpy when present and falls back to a slow pure
Python path for small test captures.  Sim mode needs no third-party modules.
"""

from __future__ import annotations

import math
import os
import struct
import time

C_KM_S = 299792.458


def rgb(r, g, b):
    return ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)


def clamp(v, lo, hi):
    return max(lo, min(hi, v))


def range_resolution_km(sample_rate_hz):
    """Bistatic range-bin size for a given sample rate."""
    if sample_rate_hz <= 0:
        return 0.0
    return C_KM_S / (2.0 * float(sample_rate_hz))


def lag_to_range_km(lag_samples, sample_rate_hz):
    if sample_rate_hz <= 0:
        return 0.0
    return C_KM_S * float(lag_samples) / (2.0 * float(sample_rate_hz))


def range_to_lag(range_km, sample_rate_hz):
    if sample_rate_hz <= 0:
        return 0
    return int(round(2.0 * float(range_km) * float(sample_rate_hz) / C_KM_S))


def normalize(matrix):
    """Return a 0..1 matrix for display, keeping dB-ish peaks readable."""
    if not matrix or not matrix[0]:
        return []
    flat = [v for row in matrix for v in row]
    lo, hi = min(flat), max(flat)
    if hi <= lo:
        return [[0.0 for _ in row] for row in matrix]
    span = hi - lo
    return [[clamp((v - lo) / span, 0.0, 1.0) for v in row] for row in matrix]


def _numpy():
    try:
        import numpy as np
        return np
    except Exception:
        return None


def read_iq(path, fmt="cs8", max_samples=262144):
    """Read IQ samples as complex values.

    Supported formats: ``cs8`` (HackRF int8 I/Q), ``cf32`` (complex64),
    ``f32`` (interleaved float32 I/Q).
    """
    fmt = (fmt or "cs8").lower()
    if not os.path.exists(path):
        raise IOError("IQ file not found: %s" % path)
    if fmt in ("cs8", "i8"):
        with open(path, "rb") as fh:
            raw = fh.read(max_samples * 2)
        n = len(raw) // 2
        vals = struct.unpack("<%db" % (n * 2), raw[: n * 2])
        return [complex(vals[i], vals[i + 1]) / 128.0 for i in range(0, len(vals), 2)]
    if fmt in ("cf32", "c64"):
        with open(path, "rb") as fh:
            raw = fh.read(max_samples * 8)
        n = min(len(raw) // 8, max_samples)
        out = []
        for i in range(n):
            re, im = struct.unpack_from("<ff", raw, i * 8)
            out.append(complex(re, im))
        return out
    if fmt == "f32":
        with open(path, "rb") as fh:
            raw = fh.read(max_samples * 8)
        n = len(raw) // 8
        vals = struct.unpack("<%df" % (n * 2), raw[: n * 2])
        return [complex(vals[i], vals[i + 1]) for i in range(0, len(vals), 2)]
    raise ValueError("unsupported IQ format: %s" % fmt)


def caf_numpy(ref, surv, sample_rate_hz, dopplers, max_lag):
    np = _numpy()
    if np is None:
        return None
    ref = np.asarray(ref, dtype=np.complex64)
    surv = np.asarray(surv, dtype=np.complex64)
    n = min(len(ref), len(surv))
    if n < 256:
        return None
    ref = ref[:n]
    surv = surv[:n]
    ref = ref - np.mean(ref)
    surv = surv - np.mean(surv)
    win = np.hanning(n)
    ref = ref * win
    surv = surv * win
    fft_len = 1 << (2 * n - 1).bit_length()
    ref_f = np.fft.rfft(ref, fft_len)
    t = np.arange(n, dtype=np.float64) / float(sample_rate_hz)
    out = []
    for dop in dopplers:
        mixed = surv * np.exp(-2j * np.pi * float(dop) * t)
        corr = np.fft.irfft(np.fft.rfft(mixed, fft_len) * np.conj(ref_f), fft_len)
        row = [float(abs(corr[i])) for i in range(0, min(max_lag + 1, n), 1)]
        out.append(row)
    # rows = range bins, cols = doppler bins
    return [list(x) for x in np.asarray(out).T.tolist()]


def caf_slow(ref, surv, sample_rate_hz, dopplers, max_lag, stride=1):
    """Pure Python CAF for short captures and tests."""
    n = min(len(ref), len(surv), 4096)
    if n < 64:
        return []
    step = max(1, stride)
    idx = list(range(0, n, step))
    ref_vals = [ref[i] for i in idx]
    surv_vals = [surv[i] for i in idx]
    ref_mean = sum(ref_vals) / len(ref_vals)
    surv_mean = sum(surv_vals) / len(surv_vals)
    ref_vals = [v - ref_mean for v in ref_vals]
    surv_vals = [v - surv_mean for v in surv_vals]
    fs = float(sample_rate_hz)
    lags = list(range(0, min(max_lag + 1, len(idx)), max(1, step)))
    out = []
    for lag in lags:
        row = []
        a = ref_vals[: len(ref_vals) - lag]
        b = surv_vals[lag:]
        for dop in dopplers:
            s = 0j
            for k, (x, y) in enumerate(zip(a, b)):
                phase = -2.0 * math.pi * float(dop) * (k * step) / fs
                s += y * x.conjugate() * complex(math.cos(phase), math.sin(phase))
            row.append(abs(s))
        out.append(row)
    return out


def caf_from_samples(ref, surv, sample_rate_hz=2000000, dopplers=None,
                     max_lag=4096, stride=1):
    dopplers = dopplers or list(range(-200, 201, 50))
    matrix = caf_numpy(ref, surv, sample_rate_hz, dopplers, max_lag)
    if not matrix:
        matrix = caf_slow(ref, surv, sample_rate_hz, dopplers, max_lag, stride)
    return matrix


def caf_from_files(ref_path, surv_path, sample_rate_hz=2000000, fmt="cs8",
                   dopplers=None, max_lag=4096, max_samples=262144,
                   stride=1):
    ref = read_iq(ref_path, fmt, max_samples)
    surv = read_iq(surv_path, fmt, max_samples)
    return caf_from_samples(ref, surv, sample_rate_hz, dopplers, max_lag, stride)


def find_peaks(matrix, min_snr=0.35, max_peaks=8, min_sep=2):
    """Pick local maxima from a normalized range x doppler matrix."""
    norm = normalize(matrix)
    if not norm:
        return []
    rows, cols = len(norm), len(norm[0])
    peaks = []
    for r in range(1, rows - 1):
        for c in range(1, cols - 1):
            v = norm[r][c]
            if v < min_snr:
                continue
            if any(v < norm[nr][nc] for nr, nc in
                   ((r - 1, c), (r + 1, c), (r, c - 1), (r, c + 1))):
                continue
            if any(abs(r - pr) <= min_sep and abs(c - pc) <= min_sep
                   for pr, pc, _ in peaks):
                continue
            peaks.append((r, c, v))
    peaks.sort(key=lambda x: -x[2])
    return peaks[:max_peaks]


def simulate_frame(t=None, seed=0, rows=18, cols=24):
    """Synthetic range/Doppler map for UI and integration tests."""
    if t is None:
        t = time.time()
    matrix = []
    for r in range(rows):
        row = []
        for c in range(cols):
            base = 0.05 + 0.035 * math.sin(r * 0.7 + c * 0.4 + t * 0.5)
            row.append(max(0.0, base))
        matrix.append(row)

    def blob(range_row, dop_col, amp):
        for r in range(rows):
            for c in range(cols):
                dr = r - range_row
                dc = c - dop_col
                v = amp * math.exp(-(dr * dr) / 2.2 - (dc * dc) / 3.0)
                matrix[r][c] += v

    blob(4 + int((t * 0.25 + seed) % 6), 7 + int((t * 0.4) % 5), 0.90)
    blob(10 + int((t * 0.13) % 5), 16 - int((t * 0.22) % 4), 0.65)
    if int(t) % 7 < 4:
        blob(14, 11, 0.42)
    return normalize(matrix)


def simulate_contacts(t=None, seed=0, sample_rate_hz=2000000, rows=18, cols=24):
    """Contacts matching simulate_frame(), in range/Doppler coordinates."""
    if t is None:
        t = time.time()
    rr = 4 + int((t * 0.25 + seed) % 6)
    cc = 7 + int((t * 0.4) % 5)
    rr2 = 10 + int((t * 0.13) % 5)
    cc2 = 16 - int((t * 0.22) % 4)
    max_range = lag_to_range_km(rows * 256, sample_rate_hz)
    doppler_span = 250.0
    def contact(num, r, c, snr):
        rng = max_range * (r + 0.5) / rows
        vel = -doppler_span + 2 * doppler_span * (c + 0.5) / cols
        return {"id": "E%02d" % num, "range_km": round(rng, 2),
                "velocity_ms": round(vel, 1), "snr": round(snr, 1),
                "row": r, "col": c, "age": 0}
    out = [contact(1, rr, cc, 24.6), contact(2, rr2, cc2, 17.2)]
    if int(t) % 7 < 4:
        out.append(contact(3, 14, 11, 11.8))
    return out
