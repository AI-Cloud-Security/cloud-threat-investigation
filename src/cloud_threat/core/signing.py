"""Software signing and trusted-key integrity verification."""
import base64
import hashlib
import time
import uuid
from datetime import datetime, timezone
from typing import Any
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
from .canonical import canonical, digest, short_id

def seal(graph: dict[str, Any], key: Ed25519PrivateKey, *, retention: str = 'exclusive-create-only-not-WORM') -> dict[str, Any]:
    """Bind graph and declared assurance metadata with a software signature."""
    payload = {
        'graph': graph,
        'issued_at': datetime.now(timezone.utc).isoformat(),
        'clock': {
            'mode': 'untrusted-host',
            'process_epoch': str(uuid.uuid4()),
            'monotonic_ns': time.monotonic_ns(),
        },
        'assurance': {
            'signing': 'software-ed25519',
            'retention': retention,
        },
    }
    return {'payload': payload, 'signature': base64.b64encode(key.sign(canonical(payload))).decode(), 'algorithm': 'Ed25519'}

def verify(bundle: dict[str, Any], trusted_public: bytes) -> dict[str, Any]:
    """Verify signature and graph integrity against the caller-selected key."""
    if bundle['algorithm'] != 'Ed25519':
        raise ValueError('Unexpected algorithm')
    Ed25519PublicKey.from_public_bytes(trusted_public).verify(base64.b64decode(bundle['signature'], validate=True), canonical(bundle['payload']))
    graph = bundle['payload']['graph']
    nodes = graph['nodes']
    root = graph['root']
    if graph['short_id'] != short_id(root):
        raise ValueError('Short identifier mismatch')
    visiting = set()
    seen = set()

    def walk(h):
        if h in visiting:
            raise ValueError('Cycle')
        if h in seen:
            return
        if h not in nodes or digest(nodes[h]) != h:
            raise ValueError('Node hash mismatch')
        visiting.add(h)
        n = nodes[h]
        if n['kind'] == 'raw':
            raw = base64.b64decode(n['data']['bytes_b64'], validate=True)
            if hashlib.sha256(raw).hexdigest() != n['data']['sha256']:
                raise ValueError('Raw byte mismatch')
        for p in n['parents']:
            walk(p)
        visiting.remove(h)
        seen.add(h)
    walk(root)
    if set(nodes) != seen:
        raise ValueError('Unreferenced nodes')
    if nodes[root]['kind'] != 'evidence':
        raise ValueError('Invalid root')
    return {'verified': True, 'root': root, 'short_id': graph['short_id'], 'scope': 'signature and graph integrity under externally pinned public key'}
