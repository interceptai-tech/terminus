"""Ed25519 verification of signed signature bundles.

A signed bundle is JSON: {"bundle": <body>, "signature": "<base64 ed25519 sig>"}
where the signature covers the canonical (sorted-key) serialization of <body>.
The sidecar pins only the public key, so it can verify but never forge.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from terminus.signature.records import SUPPORTED_BUNDLE_FORMAT_VERSIONS, SignatureBundle


class BundleVerificationError(Exception):
    """Raised when a bundle is structurally invalid or an unsupported format.

    Signature failures raise cryptography's InvalidSignature; both are handled
    fail-closed by the Update Client (keep last-known-good)."""


def load_public_key(value: str) -> Ed25519PublicKey:
    """Load the Hub public key from a PEM string, a filesystem path to a PEM file,
    or a base64-encoded raw 32-byte Ed25519 public key."""
    if "BEGIN" in value:
        key = load_pem_public_key(value.encode("utf-8"))
        if not isinstance(key, Ed25519PublicKey):
            raise BundleVerificationError("public key is not Ed25519")
        return key
    path = Path(value)
    if path.exists():
        key = load_pem_public_key(path.read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise BundleVerificationError("public key is not Ed25519")
        return key
    try:
        return Ed25519PublicKey.from_public_bytes(base64.b64decode(value))
    except ValueError as exc:  # malformed key material; binascii.Error is a ValueError subclass
        raise BundleVerificationError("could not load public key") from exc


def canonical_body(body: dict[str, Any]) -> bytes:
    """Canonical bytes the signature covers: sorted-key, no whitespace."""
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def parse_signed_bundle(raw: bytes, public_key: Ed25519PublicKey) -> SignatureBundle:
    """Verify the Ed25519 signature and parse the body. Raises InvalidSignature on
    a bad signature, BundleVerificationError on malformed/unsupported input."""
    try:
        doc = json.loads(raw)
        body = doc["bundle"]
        signature = base64.b64decode(doc["signature"])
    except (ValueError, KeyError, TypeError) as exc:
        raise BundleVerificationError("malformed signed bundle") from exc

    public_key.verify(signature, canonical_body(body))  # raises InvalidSignature

    bundle = SignatureBundle.model_validate(body)
    if bundle.bundle_format_version not in SUPPORTED_BUNDLE_FORMAT_VERSIONS:
        raise BundleVerificationError(
            f"unsupported bundle_format_version: {bundle.bundle_format_version}"
        )
    return bundle
