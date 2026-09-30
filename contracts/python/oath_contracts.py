import base64
import copy
import json
import hashlib
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def _reject_floats(value: Any) -> None:
    if isinstance(value, float):
        raise TypeError("oath-json-v1 accepts only JSON integers")
    if isinstance(value, list):
        for item in value:
            _reject_floats(item)
    elif isinstance(value, dict):
        for item in value.values():
            _reject_floats(item)


def canonical_json(value: Any) -> bytes:
    _reject_floats(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def verify_signed_document(document: dict[str, Any]) -> bool:
    detached = document.get("signature")
    if not isinstance(detached, dict):
        return False
    if detached.get("algorithm") != "ed25519":
        return False
    try:
        public_key = base64.b64decode(detached["public_key"], validate=True)
        signature = base64.b64decode(detached["signature"], validate=True)
        if len(public_key) != 32 or len(signature) != 64:
            return False
        payload = copy.deepcopy(document)
        payload["signature"] = None
        signed = canonical_json(payload)
        if detached.get("canonicalization") == "oath-json-v1+oath-domain-sha256-v1":
            domain = detached.get("domain")
            if not isinstance(domain, str) or not domain:
                return False
            domain_bytes = domain.encode("utf-8")
            signed = hashlib.sha256(
                b"oath-domain-signature-v1\0"
                + len(domain_bytes).to_bytes(8, "big")
                + domain_bytes
                + hashlib.sha256(signed).digest()
            ).digest()
        elif detached.get("canonicalization") != "oath-json-v1" or "domain" in detached:
            return False
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, signed)
        return True
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False
