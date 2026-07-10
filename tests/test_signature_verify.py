"""Ed25519 signed-bundle verification."""

import base64
import json

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from terminus.signature.verify import (
    BundleVerificationError,
    canonical_body,
    load_public_key,
    parse_signed_bundle,
)


def _body() -> dict:
    return {
        "bundle_format_version": "1",
        "fingerprint_version": "1",
        "bundle_id": "b1",
        "issued_at": "2026-06-25T00:00:00Z",
        "signatures": [
            {
                "signature_id": "sig-1",
                "query_fingerprint": "abc",
                "fingerprint_version": "1",
                "severity": "high",
                "mode": "observe",
            }
        ],
    }


def _signed(priv: Ed25519PrivateKey, body: dict) -> bytes:
    sig = priv.sign(canonical_body(body))
    return json.dumps({"bundle": body, "signature": base64.b64encode(sig).decode()}).encode()


def test_valid_signature_parses() -> None:
    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes_raw()
    pub = load_public_key(base64.b64encode(pub_pem).decode())
    bundle = parse_signed_bundle(_signed(priv, _body()), pub)
    assert bundle.signatures[0].signature_id == "sig-1"


def test_tampered_body_rejected() -> None:
    priv = Ed25519PrivateKey.generate()
    pub = load_public_key(base64.b64encode(priv.public_key().public_bytes_raw()).decode())
    raw = _signed(priv, _body())
    doc = json.loads(raw)
    doc["bundle"]["bundle_id"] = "tampered"  # body changed, signature no longer valid
    with pytest.raises(InvalidSignature):
        parse_signed_bundle(json.dumps(doc).encode(), pub)


def test_wrong_key_rejected() -> None:
    priv = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    pub_other = load_public_key(base64.b64encode(other.public_key().public_bytes_raw()).decode())
    with pytest.raises(InvalidSignature):
        parse_signed_bundle(_signed(priv, _body()), pub_other)


def test_unsupported_format_rejected() -> None:
    priv = Ed25519PrivateKey.generate()
    pub = load_public_key(base64.b64encode(priv.public_key().public_bytes_raw()).decode())
    body = _body()
    body["bundle_format_version"] = "999"
    with pytest.raises(BundleVerificationError):
        parse_signed_bundle(_signed(priv, body), pub)


def _public_pem(priv: Ed25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def test_load_public_key_from_pem_string() -> None:
    priv = Ed25519PrivateKey.generate()
    pub = load_public_key(_public_pem(priv).decode())
    bundle = parse_signed_bundle(_signed(priv, _body()), pub)
    assert bundle.signatures[0].signature_id == "sig-1"


def test_load_public_key_from_pem_path(tmp_path) -> None:
    priv = Ed25519PrivateKey.generate()
    key_file = tmp_path / "hub_pub.pem"
    key_file.write_bytes(_public_pem(priv))
    pub = load_public_key(str(key_file))
    bundle = parse_signed_bundle(_signed(priv, _body()), pub)
    assert bundle.signatures[0].signature_id == "sig-1"
