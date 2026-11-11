"""Encoding primitives: base58btc, multibase, multihash, Multikey and JCS.

Only the subset needed by did:content is implemented:
- multibase: base58btc (prefix ``z``)
- multihash: sha2-256 (code 0x12, length 0x20)
- multikey:  Ed25519 public keys (multicodec prefix 0xed01)
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MULTIBASE_BASE58BTC = "z"
MULTIHASH_SHA2_256 = b"\x12\x20"
MULTICODEC_ED25519_PUB = b"\xed\x01"


def b58encode(data: bytes) -> str:
    """Encode bytes as base58btc (Bitcoin alphabet, leading zeros -> '1')."""
    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    number = int.from_bytes(data, "big")
    digits: list[str] = []
    while number > 0:
        number, remainder = divmod(number, 58)
        digits.append(B58_ALPHABET[remainder])
    return "1" * leading_zeros + "".join(reversed(digits))


def b58decode(text: str) -> bytes:
    """Decode a base58btc string. Raises ValueError on invalid characters."""
    number = 0
    for char in text:
        index = B58_ALPHABET.find(char)
        if index < 0:
            raise ValueError(f"invalid base58 character: {char!r}")
        number = number * 58 + index
    leading_ones = len(text) - len(text.lstrip("1"))
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * leading_ones + body


def multibase_encode(data: bytes) -> str:
    """Multibase-encode bytes with base58btc (prefix 'z')."""
    return MULTIBASE_BASE58BTC + b58encode(data)


def multibase_decode(text: str) -> bytes:
    """Decode a multibase string. Only base58btc ('z') is supported."""
    if not text or text[0] != MULTIBASE_BASE58BTC:
        raise ValueError("only base58btc multibase ('z' prefix) is supported")
    return b58decode(text[1:])


def multihash_sha256(data: bytes) -> str:
    """Return multibase(base58btc) of multihash(sha2-256) of ``data``."""
    digest = hashlib.sha256(data).digest()
    return multibase_encode(MULTIHASH_SHA2_256 + digest)


def multikey_ed25519(public_key: bytes) -> str:
    """Encode a raw 32-byte Ed25519 public key as a Multikey string (z6Mk...)."""
    if len(public_key) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return multibase_encode(MULTICODEC_ED25519_PUB + public_key)


def multikey_decode_ed25519(multikey: str) -> bytes:
    """Decode a Multikey string into raw Ed25519 public key bytes."""
    raw = multibase_decode(multikey)
    if not raw.startswith(MULTICODEC_ED25519_PUB) or len(raw) != 34:
        raise ValueError("not an Ed25519 Multikey")
    return raw[2:]


def multikey_hash(multikey: str) -> str:
    """Hash of a Multikey string, used by key pre-rotation (nextKeyHashes)."""
    return multihash_sha256(multikey.encode("utf-8"))


def jcs(value: Any) -> bytes:
    """JSON Canonicalization Scheme (RFC 8785) serialization.

    Python's json module matches JCS for objects, arrays, strings, booleans,
    null and integers. Floats are rejected here because their JCS formatting
    differs from Python's; did:content documents never need them.
    """
    _reject_floats(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _reject_floats(value: Any) -> None:
    if isinstance(value, float):
        raise ValueError("floating point numbers are not allowed in did:content documents")
    if isinstance(value, dict):
        for item in value.values():
            _reject_floats(item)
    elif isinstance(value, list):
        for item in value:
            _reject_floats(item)
