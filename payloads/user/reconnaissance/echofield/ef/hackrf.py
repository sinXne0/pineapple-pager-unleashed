#!/usr/bin/env python3
"""HackRF capture helper for ECHOFIELD.

ECHOFIELD needs two coherent channels for a real cross-ambiguity function:
one antenna pointed at the illuminator (reference) and one pointed at the
surveillance area.  A single HackRF One is half-duplex and cannot do that by
itself, so this helper expects either:

* two HackRFs sharing a 10 MHz reference clock, or
* an external capture command set in ``ECHOFIELD_CAPTURE``.

If ``ECHOFIELD_CAPTURE`` is set, it is executed with these arguments:

    <command> <freq_hz> <sample_rate> <samples> <ref_path> <surv_path>

The command must write two IQ files.  Otherwise this module calls
``hackrf_transfer`` twice with the serial numbers in
``ECHOFIELD_HACKRF_REF`` and ``ECHOFIELD_HACKRF_SURV``.
"""

from __future__ import annotations

import os
import shutil
import subprocess

from . import radar


def available():
    return shutil.which("hackrf_transfer") is not None or bool(os.environ.get("ECHOFIELD_CAPTURE"))


def _run_capture(freq_hz, sample_rate, samples, ref_path, surv_path, gain):
    custom = os.environ.get("ECHOFIELD_CAPTURE")
    if custom:
        cmd = [custom, str(int(freq_hz)), str(int(sample_rate)), str(int(samples)),
               ref_path, surv_path]
        subprocess.check_call(cmd)
        return

    hackrf = shutil.which("hackrf_transfer")
    if not hackrf:
        raise RuntimeError("hackrf_transfer not installed and ECHOFIELD_CAPTURE is unset")

    serials = (
        os.environ.get("ECHOFIELD_HACKRF_REF", ""),
        os.environ.get("ECHOFIELD_HACKRF_SURV", ""),
    )
    if not all(serials):
        raise RuntimeError("set ECHOFIELD_HACKRF_REF and ECHOFIELD_HACKRF_SURV, "
                           "or use ECHOFIELD_CAPTURE")

    procs = []
    for serial, path in zip(serials, (ref_path, surv_path)):
        cmd = [
            hackrf, "-d", serial, "-r", path,
            "-f", str(int(freq_hz)), "-s", str(int(sample_rate)),
            "-n", str(int(samples)), "-l", str(int(gain)), "-g", "0",
        ]
        procs.append(subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.PIPE))
    for proc in procs:
        _, err = proc.communicate()
        if proc.returncode:
            raise RuntimeError("hackrf_transfer failed: %s" % err.decode("utf-8", "replace").strip())


def capture_caf(freq_mhz=100.1, sample_rate_hz=2000000, samples=262144,
                gain=24, fmt="cs8", dopplers=None, max_lag=4096,
                workdir="/tmp/echofield_capture", stride=1):
    os.makedirs(workdir, exist_ok=True)
    ref_path = os.path.join(workdir, "ref.cs8")
    surv_path = os.path.join(workdir, "surv.cs8")
    _run_capture(float(freq_mhz) * 1e6, sample_rate_hz, samples,
                 ref_path, surv_path, gain)
    return radar.caf_from_files(ref_path, surv_path, sample_rate_hz,
                                fmt=fmt, dopplers=dopplers,
                                max_lag=max_lag, stride=stride)
