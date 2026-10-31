"""Deterministic encoding and content identifiers."""
import base64
import hashlib
import json
from typing import Any

def canonical(x: Any) -> bytes:
    """Project encoding v1: ASCII keys, integer values, UTF-8 strings. Not RFC8785."""

    def check(v):
        if v is None or isinstance(v, (str, bool, int)):
            return
        if isinstance(v, list):
            for z in v:
                check(z)
            return
        if isinstance(v, dict) and all((isinstance(k, str) and k.isascii() for k in v)):
            for z in v.values():
                check(z)
            return
        raise ValueError('Only integer JSON and ASCII object keys supported')
    check(x)
    return json.dumps(x, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf8')

def digest(x: Any) -> str:
    """Hash a value under the project encoding."""
    return hashlib.sha256(canonical(x)).hexdigest()

def short_id(root: str) -> str:
    """Return a checksum-protected convenience reference for a full root."""
    raw = bytes.fromhex(root)[:15]
    checksum = hashlib.sha256(raw).digest()[:3]
    return base64.b32encode(raw + checksum).decode().rstrip('=')
