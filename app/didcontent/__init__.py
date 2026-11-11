"""Reference implementation of the did:content DID method (v0.2 draft).

Pure-Python apart from `cryptography`, which is used for Ed25519 signatures.
The package is intentionally small so that it can be read alongside the
specification in README.md. Nothing here is production hardened.
"""

from .encoding import (
    b58decode,
    b58encode,
    jcs,
    multibase_decode,
    multibase_encode,
    multihash_sha256,
    multikey_ed25519,
    multikey_hash,
)
from .log import (
    METHOD_ID,
    SCID_PLACEHOLDER,
    DidContentError,
    LogSigner,
    append_entry,
    content_binding,
    create_genesis,
    did_from_scid,
    resolve,
    verify_log,
)

__all__ = [
    "METHOD_ID",
    "SCID_PLACEHOLDER",
    "DidContentError",
    "LogSigner",
    "append_entry",
    "b58decode",
    "b58encode",
    "content_binding",
    "create_genesis",
    "did_from_scid",
    "jcs",
    "multibase_decode",
    "multibase_encode",
    "multihash_sha256",
    "multikey_ed25519",
    "multikey_hash",
    "resolve",
    "verify_log",
]
