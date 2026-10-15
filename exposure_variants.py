"""Conservative byte-equivalent spellings to watch in outbound model requests."""
from __future__ import annotations

import base64
import json
from urllib.parse import quote


def exposure_variants(value: str) -> frozenset[str]:
    """Match exact values and common lossless encodings, not arbitrary fragments."""
    variants = {value}
    raw = value.encode("utf-8")
    if len(raw) >= 12:
        variants.add(base64.b64encode(raw).decode("ascii"))
        variants.add(raw.hex())
        variants.add(raw.hex().upper())
        variants.add(quote(value, safe=""))
        variants.add(json.dumps(value, ensure_ascii=True)[1:-1])
    return frozenset(variants)
