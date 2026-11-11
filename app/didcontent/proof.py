"""Data Integrity proofs using the ``eddsa-jcs-2022`` cryptosuite.

See W3C "Data Integrity EdDSA Cryptosuites v1.0" (Recommendation, 2025-05-15).
Hashing: sha256(JCS(proofConfig)) || sha256(JCS(unsecuredDocument)).
"""

from __future__ import annotations

import copy
import hashlib
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .encoding import jcs, multibase_decode, multibase_encode, multikey_decode_ed25519

PROOF_TYPE = "DataIntegrityProof"
CRYPTOSUITE = "eddsa-jcs-2022"
PROOF_PURPOSE = "assertionMethod"


def did_key_verification_method(multikey: str) -> str:
    """did:key URL for a Multikey, e.g. did:key:z6Mk...#z6Mk..."""
    return f"did:key:{multikey}#{multikey}"


def _hash_data(unsecured_document: dict[str, Any], proof_config: dict[str, Any]) -> bytes:
    config = copy.deepcopy(proof_config)
    config.pop("proofValue", None)
    if "@context" in unsecured_document:
        config["@context"] = unsecured_document["@context"]
    return hashlib.sha256(jcs(config)).digest() + hashlib.sha256(jcs(unsecured_document)).digest()


def create_proof(
    unsecured_document: dict[str, Any],
    private_key: Ed25519PrivateKey,
    verification_method: str,
    created: str,
) -> dict[str, Any]:
    """Return an eddsa-jcs-2022 proof over ``unsecured_document``."""
    proof: dict[str, Any] = {
        "type": PROOF_TYPE,
        "cryptosuite": CRYPTOSUITE,
        "verificationMethod": verification_method,
        "created": created,
        "proofPurpose": PROOF_PURPOSE,
    }
    signature = private_key.sign(_hash_data(unsecured_document, proof))
    return {**proof, "proofValue": multibase_encode(signature)}


def verify_proof(unsecured_document: dict[str, Any], proof: dict[str, Any]) -> bool:
    """Verify a single eddsa-jcs-2022 proof. Returns False instead of raising."""
    if proof.get("type") != PROOF_TYPE or proof.get("cryptosuite") != CRYPTOSUITE:
        return False
    try:
        multikey = multikey_from_verification_method(proof["verificationMethod"])
        public_key = Ed25519PublicKey.from_public_bytes(multikey_decode_ed25519(multikey))
        public_key.verify(multibase_decode(proof["proofValue"]), _hash_data(unsecured_document, proof))
        return True
    except (KeyError, ValueError, InvalidSignature):
        return False


def multikey_from_verification_method(verification_method: str) -> str:
    """Extract the Multikey from ``did:key:<mk>#<mk>`` (or ``did:key:<mk>``)."""
    if not verification_method.startswith("did:key:"):
        raise ValueError("log entry proofs must use did:key verification methods")
    return verification_method[len("did:key:"):].split("#", 1)[0]
