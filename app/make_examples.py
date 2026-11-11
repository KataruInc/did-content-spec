#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regenerate the test vectors in ../examples (deterministic; keys are TEST ONLY)."""

from __future__ import annotations

import copy
import json
import struct
import zlib
from pathlib import Path

from didcontent import LogSigner, append_entry, content_binding, create_genesis, multikey_hash, resolve
from didcontent.log import dump_log

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
# Deterministic seeds so that the published vectors are reproducible. Never reuse them.
SEED_GENESIS = bytes.fromhex("00" * 31 + "01")
SEED_ROTATED = bytes.fromhex("00" * 31 + "02")
CONTEXT = ["https://www.w3.org/ns/did/v1.1", "https://did.kataru.io/did-content/v1"]


def sample_png() -> bytes:
    """An 8x8 RGB gradient PNG built with the standard library."""
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    rows = b"".join(b"\x00" + bytes(v for x in range(8) for v in (x * 32, y * 32, 128)) for y in range(8))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 8, 8, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b""))


def main() -> None:
    EXAMPLES.mkdir(exist_ok=True)
    png = sample_png()
    (EXAMPLES / "sample.png").write_bytes(png)

    genesis_signer = LogSigner.from_seed(SEED_GENESIS)
    rotated_signer = LogSigner.from_seed(SEED_ROTATED)
    creator = f"did:key:{genesis_signer.multikey}"

    state = {
        "@context": CONTEXT,
        "id": "did:content:{SCID}",
        "controller": [creator],
        "verificationMethod": [{
            "id": "did:content:{SCID}#key-1",
            "type": "Multikey",
            "controller": "did:content:{SCID}",
            "publicKeyMultibase": genesis_signer.multikey,
        }],
        "assertionMethod": ["did:content:{SCID}#key-1"],
        "capabilityInvocation": ["did:content:{SCID}#key-1"],
        "content": content_binding(png, "image/png", ["https://cdn.example.com/sample.png"]),
        "parties": [
            {"id": "did:content:{SCID}#party-1", "role": "creator", "party": creator},
            {"id": "did:content:{SCID}#party-2", "role": "rightsHolder", "party": "did:web:label.example.com"},
        ],
        "license": [{
            "id": "did:content:{SCID}#license-1",
            "type": "RSLLicense",
            "permits": {"usage": ["search"], "user": ["commercial", "non-commercial"]},
            "prohibits": {"usage": ["ai-train", "ai-input"]},
            "payment": {"type": "attribution"},
            "terms": "https://label.example.com/licenses/standard",
        }],
        "royalty": {"recipients": [
            {"party": "did:content:{SCID}#party-1", "shareBasisPoints": 8000, "payTo": "did:pkh:eip155:1:0x0000000000000000000000000000000000000001"},
            {"party": "did:content:{SCID}#party-2", "shareBasisPoints": 2000, "payTo": "payto:iban/DE75512108001245126199"},
        ]},
        "service": [{
            "id": "did:content:{SCID}#delivery",
            "type": "ContentDelivery",
            "serviceEndpoint": "https://cdn.example.com/sample.png",
        }],
    }
    # softBindings (e.g. ISCC, alg "io.iscc.v0") are omitted here because the
    # reference tool does not compute them; see README "Soft bindings".

    genesis = create_genesis(
        state, genesis_signer, version_time="2026-11-01T00:00:00Z",
        next_key_hashes=[multikey_hash(rotated_signer.multikey)],
        extra_parameters={"registries": ["https://did.kataru.io"], "ttl": 3600},
    )

    # Version 2: the content moved to IPFS, the key was rotated, AI training is now licensed.
    state2 = copy.deepcopy(genesis["state"])
    state2["content"]["locations"] = ["ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi", "https://cdn.example.com/sample.png"]
    state2["license"].append({
        "id": f"{genesis['state']['id']}#license-2",
        "type": "RSLLicense",
        "permits": {"usage": ["ai-train"], "user": ["commercial"]},
        "payment": {"type": "training", "terms": "https://label.example.com/licenses/ai-training"},
    })
    entry2 = append_entry(
        [genesis], state2, genesis_signer,
        {"updateKeys": [rotated_signer.multikey], "nextKeyHashes": []},
        version_time="2026-11-10T00:00:00Z",
    )

    log = [genesis, entry2]
    (EXAMPLES / "did.jsonl").write_text(dump_log(log))
    (EXAMPLES / "did-document.json").write_text(json.dumps(entry2["state"], indent=2, ensure_ascii=False) + "\n")
    (EXAMPLES / "resolution-result.json").write_text(json.dumps(resolve(log), indent=2, ensure_ascii=False) + "\n")
    (EXAMPLES / "resolution-result-v1.json").write_text(
        json.dumps(resolve(log, version_id=genesis["versionId"]), indent=2, ensure_ascii=False) + "\n")
    print(genesis["state"]["id"])


if __name__ == "__main__":
    main()
