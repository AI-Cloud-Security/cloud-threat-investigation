"""Persistent local signing identity and signed workflow documents."""
import base64
import hashlib
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from cloud_threat.core.canonical import canonical


def load_identity(workspace: Path) -> Ed25519PrivateKey:
    """Keep the local software key outside source and exported artifacts."""
    workspace.mkdir(parents=True, exist_ok=True)
    key_path = workspace / 'signing-key.bin'
    if key_path.exists():
        return Ed25519PrivateKey.from_private_bytes(key_path.read_bytes())
    # Losing the key for an existing database must never silently create a new identity.
    if (workspace / 'investigations.sqlite3').exists():
        raise ValueError('Workspace signing key is missing. Restore the matching key from backup.')
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())
    descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
    return key


def public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def fingerprint(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()


def sign_document(payload: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    return {'payload': payload, 'algorithm': 'Ed25519',
            'signature': base64.b64encode(key.sign(canonical(payload))).decode('ascii')}


def verify_document(document: dict[str, Any], trusted_key: bytes) -> dict[str, Any]:
    if document.get('algorithm') != 'Ed25519':
        raise ValueError('Unsupported signature algorithm')
    Ed25519PublicKey.from_public_bytes(trusted_key).verify(
        base64.b64decode(document['signature'], validate=True), canonical(document['payload']))
    return document['payload']
