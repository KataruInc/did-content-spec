"""did:content DID Log: creation, verification and resolution.

A DID Log is a JSON Lines file (``did.jsonl``). Each line is a *log entry*::

    {"versionId": "<n>-<entryHash>", "versionTime": "...", "parameters": {...},
     "state": {<DID document>}, "proof": [<DataIntegrityProof>]}

The first entry fixes the Self-Certifying Identifier (SCID) and the content
hard bindings. Later entries may rotate keys, move the content or change
licensing, but can never remove a hard binding or change the DID.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .encoding import jcs, multihash_sha256, multikey_ed25519, multikey_hash
from .proof import (
    create_proof,
    did_key_verification_method,
    multikey_from_verification_method,
    verify_proof,
)

METHOD_ID = "did:content:0.2"
SUPPORTED_METHODS = frozenset({METHOD_ID})
SCID_PLACEHOLDER = "{SCID}"
DID_PREFIX = "did:content:"
ENTRY_KEYS = frozenset({"versionId", "versionTime", "parameters", "state", "proof"})
# Resolvers tolerate this much clock skew when rejecting future-dated entries.
MAX_CLOCK_SKEW = timedelta(minutes=5)
DID_DOCUMENT_MEDIA_TYPE = "application/did"
RESOLUTION_CONTEXT = "https://w3id.org/did-resolution/v1"


class DidContentError(Exception):
    """Raised when a DID Log violates the did:content method rules."""


@dataclass(frozen=True)
class LogSigner:
    """An Ed25519 key authorized to sign log entries (an ``updateKey``)."""

    private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "LogSigner":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> "LogSigner":
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @property
    def multikey(self) -> str:
        from cryptography.hazmat.primitives import serialization

        raw = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return multikey_ed25519(raw)

    @property
    def verification_method(self) -> str:
        return did_key_verification_method(self.multikey)


@dataclass
class VerifiedLog:
    did: str
    scid: str
    entries: list[dict[str, Any]]
    active_parameters: dict[str, Any] = field(default_factory=dict)

    @property
    def deactivated(self) -> bool:
        return bool(self.active_parameters.get("deactivated", False))


def did_from_scid(scid: str) -> str:
    return DID_PREFIX + scid


def content_binding(data: bytes, media_type: str, locations: list[str] | None = None) -> dict[str, Any]:
    """Build the ``content`` property for a DID document from raw content bytes."""
    binding: dict[str, Any] = {
        "mediaType": media_type,
        "byteLength": len(data),
        "hardBindings": [{"digestMultibase": multihash_sha256(data)}],
    }
    if locations:
        binding["locations"] = list(locations)
    return binding


def _replace_strings(value: Any, old: str, new: str) -> Any:
    if isinstance(value, str):
        return value.replace(old, new)
    if isinstance(value, dict):
        return {key: _replace_strings(item, old, new) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_strings(item, old, new) for item in value]
    return value


def _entry_hash(unsecured_entry: dict[str, Any], previous_version_id: str) -> str:
    return multihash_sha256(jcs({**unsecured_entry, "versionId": previous_version_id}))


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def create_genesis(
    state: dict[str, Any],
    signer: LogSigner,
    version_time: str | None = None,
    next_key_hashes: list[str] | None = None,
    extra_parameters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create the first log entry. ``state['id']`` must contain ``{SCID}``."""
    if SCID_PLACEHOLDER not in state.get("id", ""):
        raise DidContentError("genesis state.id must be 'did:content:{SCID}'")
    if not state.get("content", {}).get("hardBindings"):
        raise DidContentError("genesis state must include content.hardBindings")
    version_time = version_time or _now()
    parameters: dict[str, Any] = {
        "method": METHOD_ID,
        "scid": SCID_PLACEHOLDER,
        "updateKeys": [signer.multikey],
        **(extra_parameters or {}),
    }
    if next_key_hashes is not None:
        parameters["nextKeyHashes"] = list(next_key_hashes)
    preliminary = {
        "versionId": SCID_PLACEHOLDER,
        "versionTime": version_time,
        "parameters": parameters,
        "state": copy.deepcopy(state),
    }
    scid = multihash_sha256(jcs(preliminary))
    entry = _replace_strings(preliminary, SCID_PLACEHOLDER, scid)
    entry["versionId"] = f"1-{_entry_hash(entry, scid)}"
    proof = create_proof(entry, signer.private_key, signer.verification_method, version_time)
    return {**entry, "proof": [proof]}


def append_entry(
    log: list[dict[str, Any]],
    state: dict[str, Any],
    signer: LogSigner,
    parameters: dict[str, Any] | None = None,
    version_time: str | None = None,
) -> dict[str, Any]:
    """Create the next log entry signed by ``signer`` (must be an active updateKey)."""
    if not log:
        raise DidContentError("cannot append to an empty log; use create_genesis")
    previous = log[-1]
    number = int(previous["versionId"].split("-", 1)[0]) + 1
    version_time = version_time or _now()
    entry = {
        "versionId": previous["versionId"],
        "versionTime": version_time,
        "parameters": dict(parameters or {}),
        "state": copy.deepcopy(state),
    }
    entry["versionId"] = f"{number}-{_entry_hash(entry, previous['versionId'])}"
    proof = create_proof(entry, signer.private_key, signer.verification_method, version_time)
    return {**entry, "proof": [proof]}


def _parse_time(text: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise DidContentError(f"invalid versionTime: {text!r}") from error
    if parsed.tzinfo is None:
        raise DidContentError("versionTime must carry a timezone")
    return parsed


def _hard_bindings(state: dict[str, Any]) -> list[str]:
    bindings = state.get("content", {}).get("hardBindings", [])
    digests = [item.get("digestMultibase") for item in bindings if isinstance(item, dict)]
    if any(not isinstance(digest, str) for digest in digests):
        raise DidContentError("every hardBinding needs a digestMultibase string")
    return digests


def _verify_scid(first: dict[str, Any]) -> str:
    parameters = first.get("parameters", {})
    if parameters.get("method") not in SUPPORTED_METHODS:
        raise DidContentError(f"unsupported method parameter: {parameters.get('method')!r}")
    scid = parameters.get("scid")
    if not isinstance(scid, str) or not scid:
        raise DidContentError("first entry must declare parameters.scid")
    preliminary = {key: value for key, value in first.items() if key != "proof"}
    preliminary["versionId"] = SCID_PLACEHOLDER
    preliminary = _replace_strings(preliminary, scid, SCID_PLACEHOLDER)
    if multihash_sha256(jcs(preliminary)) != scid:
        raise DidContentError("SCID does not match the first log entry")
    return scid


def _verify_proofs(entry: dict[str, Any], authorized_keys: list[str]) -> None:
    proofs = entry.get("proof")
    if not isinstance(proofs, list) or not proofs:
        raise DidContentError(f"entry {entry['versionId']} has no proof")
    unsecured = {key: value for key, value in entry.items() if key != "proof"}
    for proof in proofs:
        try:
            multikey = multikey_from_verification_method(proof.get("verificationMethod", ""))
        except ValueError:
            continue
        if multikey in authorized_keys and verify_proof(unsecured, proof):
            return
    raise DidContentError(f"entry {entry['versionId']} is not signed by an authorized updateKey")


def _check_pre_rotation(parameters: dict[str, Any], active: dict[str, Any], version_id: str) -> None:
    if not active.get("nextKeyHashes"):
        return
    if "updateKeys" not in parameters or "nextKeyHashes" not in parameters:
        raise DidContentError(f"entry {version_id}: pre-rotation requires explicit updateKeys and nextKeyHashes")
    for key in parameters["updateKeys"]:
        if multikey_hash(key) not in active["nextKeyHashes"]:
            raise DidContentError(f"entry {version_id}: updateKey {key} was not pre-rotated")


def verify_log(entries: list[dict[str, Any]]) -> VerifiedLog:
    """Verify a full DID Log. Raises DidContentError on the first violation."""
    if not entries:
        raise DidContentError("empty DID log")
    scid = _verify_scid(entries[0])
    did = did_from_scid(scid)
    active: dict[str, Any] = {}
    previous_version_id = scid
    previous_time: datetime | None = None
    previous_bindings: list[str] | None = None
    deadline = datetime.now(timezone.utc) + MAX_CLOCK_SKEW

    for index, entry in enumerate(entries, start=1):
        if set(entry) != ENTRY_KEYS:
            raise DidContentError(f"entry {index} has unexpected keys: {sorted(entry)}")
        version_id = entry["versionId"]
        number, _, _ = version_id.partition("-")
        if number != str(index):
            raise DidContentError(f"entry {index} has versionId {version_id!r}")
        unsecured = {key: value for key, value in entry.items() if key != "proof"}
        if _entry_hash(unsecured, previous_version_id) != version_id.split("-", 1)[1]:
            raise DidContentError(f"entry {version_id}: entryHash mismatch")

        time = _parse_time(entry["versionTime"])
        if (previous_time and time < previous_time) or time > deadline:
            raise DidContentError(f"entry {version_id}: versionTime out of order or in the future")

        if active.get("deactivated"):
            raise DidContentError(f"entry {version_id}: DID is already deactivated")
        parameters = entry["parameters"]
        if index > 1 and "scid" in parameters:
            raise DidContentError(f"entry {version_id}: scid may only appear in the first entry")
        if index > 1 and "method" in parameters and parameters["method"] not in SUPPORTED_METHODS:
            raise DidContentError(f"entry {version_id}: unsupported method {parameters['method']!r}")

        authorized = parameters.get("updateKeys", []) if index == 1 else active.get("updateKeys", [])
        if not authorized:
            raise DidContentError(f"entry {version_id}: no authorized updateKeys")
        if index > 1:
            _check_pre_rotation(parameters, active, version_id)
        _verify_proofs(entry, authorized)

        state = entry["state"]
        if state.get("id") != did:
            raise DidContentError(f"entry {version_id}: state.id must be {did}")
        bindings = _hard_bindings(state)
        if index == 1 and not bindings:
            raise DidContentError("first entry must bind content via content.hardBindings")
        if previous_bindings and not set(previous_bindings) <= set(bindings):
            raise DidContentError(f"entry {version_id}: hard bindings may not be removed or altered")

        active = {**active, **parameters}
        if active.get("deactivated") and active.get("updateKeys"):
            raise DidContentError(f"entry {version_id}: deactivation must set updateKeys to []")
        previous_version_id, previous_time, previous_bindings = version_id, time, bindings

    return VerifiedLog(did=did, scid=scid, entries=list(entries), active_parameters=active)


def _select_entry(verified: VerifiedLog, version_id: str | None, version_time: str | None) -> int:
    if version_id is not None:
        for index, entry in enumerate(verified.entries):
            if entry["versionId"] == version_id:
                return index
        raise DidContentError(f"versionId {version_id!r} not found")
    if version_time is not None:
        wanted = _parse_time(version_time)
        candidates = [i for i, e in enumerate(verified.entries) if _parse_time(e["versionTime"]) <= wanted]
        if not candidates:
            raise DidContentError(f"no version existed at {version_time}")
        return candidates[-1]
    return len(verified.entries) - 1


def resolve(
    entries: list[dict[str, Any]],
    version_id: str | None = None,
    version_time: str | None = None,
) -> dict[str, Any]:
    """Verify the log and build a DID Resolution result (W3C DID Resolution v0.3)."""
    verified = verify_log(entries)
    index = _select_entry(verified, version_id, version_time)
    selected = verified.entries[index]
    metadata: dict[str, Any] = {
        "created": verified.entries[0]["versionTime"],
        "updated": selected["versionTime"],
        "versionId": selected["versionId"],
        "deactivated": verified.deactivated,
    }
    if index + 1 < len(verified.entries):
        following = verified.entries[index + 1]
        metadata["nextVersionId"] = following["versionId"]
        metadata["nextUpdate"] = following["versionTime"]
    return {
        "@context": RESOLUTION_CONTEXT,
        "didDocument": selected["state"],
        "didDocumentMetadata": metadata,
        "didResolutionMetadata": {"contentType": DID_DOCUMENT_MEDIA_TYPE},
    }


def load_log(text: str) -> list[dict[str, Any]]:
    """Parse a did.jsonl document."""
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def dump_log(entries: list[dict[str, Any]]) -> str:
    """Serialize entries as JSON Lines (one JCS-canonical entry per line)."""
    return "".join(jcs(entry).decode("utf-8") + "\n" for entry in entries)
