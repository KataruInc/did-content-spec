#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Command line reference tool for did:content (v0.2 draft).

Examples::

    # 1. generate an update key (writes a 32-byte hex seed; keep it secret)
    python3 content_did.py keygen --out key.hex

    # 2. create a DID for a file and write the DID Log
    python3 content_did.py create --key key.hex --content photo.jpg \
        --media-type image/jpeg --location https://cdn.example/photo.jpg \
        --out did.jsonl

    # 3. verify / resolve a DID Log
    python3 content_did.py verify did.jsonl
    python3 content_did.py resolve did.jsonl --version-id 1-zQm...

    # 4. check that a file matches the DID document's hard binding
    python3 content_did.py check did.jsonl photo.jpg
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
from pathlib import Path

from didcontent import (
    DidContentError,
    LogSigner,
    content_binding,
    create_genesis,
    multihash_sha256,
    resolve,
    verify_log,
)
from didcontent.log import load_log, dump_log

CONTEXT = [
    "https://www.w3.org/ns/did/v1.1",
    "https://did.kataru.io/did-content/v1",
]


def _read_signer(path: str) -> LogSigner:
    return LogSigner.from_seed(bytes.fromhex(Path(path).read_text().strip()))


def cmd_keygen(args: argparse.Namespace) -> int:
    seed = secrets.token_bytes(32)
    Path(args.out).write_text(seed.hex() + "\n")
    print(f"updateKey (Multikey): {LogSigner.from_seed(seed).multikey}")
    print(f"seed written to {args.out} (keep it secret)")
    return 0


def cmd_hash(args: argparse.Namespace) -> int:
    print(multihash_sha256(Path(args.file).read_bytes()))
    return 0


def cmd_create(args: argparse.Namespace) -> int:
    signer = _read_signer(args.key)
    data = Path(args.content).read_bytes()
    state = {
        "@context": CONTEXT,
        "id": "did:content:{SCID}",
        "controller": [args.controller] if args.controller else [f"did:key:{signer.multikey}"],
        "content": content_binding(data, args.media_type, args.location),
    }
    entry = create_genesis(state, signer)
    Path(args.out).write_text(dump_log([entry]))
    print(entry["state"]["id"])
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    verified = verify_log(load_log(Path(args.log).read_text()))
    status = "deactivated" if verified.deactivated else "active"
    print(f"OK {verified.did} ({len(verified.entries)} entries, {status})")
    return 0


def cmd_resolve(args: argparse.Namespace) -> int:
    result = resolve(load_log(Path(args.log).read_text()), args.version_id, args.version_time)
    json.dump(result, sys.stdout, indent=2, ensure_ascii=False)
    print()
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    document = resolve(load_log(Path(args.log).read_text()))["didDocument"]
    digests = {b["digestMultibase"] for b in document.get("content", {}).get("hardBindings", [])}
    actual = multihash_sha256(Path(args.file).read_bytes())
    if actual in digests:
        print(f"MATCH {actual}")
        return 0
    print(f"MISMATCH file={actual} document={sorted(digests)}")
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="did:content reference tool")
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="generate an Ed25519 update key seed")
    keygen.add_argument("--out", default="key.hex")
    keygen.set_defaults(func=cmd_keygen)

    hash_cmd = sub.add_parser("hash", help="print the digestMultibase of a file")
    hash_cmd.add_argument("file")
    hash_cmd.set_defaults(func=cmd_hash)

    create = sub.add_parser("create", help="create a DID Log for a content file")
    create.add_argument("--key", required=True, help="hex seed file from keygen")
    create.add_argument("--content", required=True)
    create.add_argument("--media-type", required=True)
    create.add_argument("--location", action="append", default=[], help="URL where the bytes are served")
    create.add_argument("--controller", help="controller DID (defaults to the update key's did:key)")
    create.add_argument("--out", default="did.jsonl")
    create.set_defaults(func=cmd_create)

    verify = sub.add_parser("verify", help="verify a DID Log")
    verify.add_argument("log")
    verify.set_defaults(func=cmd_verify)

    resolve_cmd = sub.add_parser("resolve", help="verify and print a DID Resolution result")
    resolve_cmd.add_argument("log")
    resolve_cmd.add_argument("--version-id")
    resolve_cmd.add_argument("--version-time")
    resolve_cmd.set_defaults(func=cmd_resolve)

    check = sub.add_parser("check", help="check a file against the DID document hard bindings")
    check.add_argument("log")
    check.add_argument("file")
    check.set_defaults(func=cmd_check)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (DidContentError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
