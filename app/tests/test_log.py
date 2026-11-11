# SPDX-License-Identifier: MIT
"""Tests for the did:content reference implementation (run: python3 -m unittest)."""

from __future__ import annotations

import copy
import json
import unittest

from didcontent import (
    DidContentError,
    LogSigner,
    append_entry,
    content_binding,
    create_genesis,
    multikey_hash,
    resolve,
    verify_log,
)
from didcontent.encoding import b58decode, b58encode, jcs, multihash_sha256
from didcontent.log import dump_log, load_log

SEED_A = bytes(range(32))
SEED_B = bytes(range(32, 64))
CONTENT = b"hello did:content"
T1, T2, T3 = "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z"


def genesis_state(signer: LogSigner) -> dict:
    return {
        "id": "did:content:{SCID}",
        "controller": [f"did:key:{signer.multikey}"],
        "content": content_binding(CONTENT, "text/plain", ["https://example.com/hello.txt"]),
        "parties": [{"id": "did:content:{SCID}#party-1", "role": "creator", "party": f"did:key:{signer.multikey}"}],
    }


class EncodingTests(unittest.TestCase):
    def test_base58_roundtrip_with_leading_zeros(self) -> None:
        data = b"\x00\x00hello"
        self.assertEqual(b58decode(b58encode(data)), data)

    def test_multihash_sha256_is_self_describing(self) -> None:
        digest = multihash_sha256(b"abc")
        self.assertTrue(digest.startswith("zQm"))  # z = base58btc, Qm = sha2-256 multihash
        self.assertEqual(b58decode(digest[1:])[:2], b"\x12\x20")

    def test_jcs_sorts_keys_and_rejects_floats(self) -> None:
        self.assertEqual(jcs({"b": 1, "a": [True, None]}), b'{"a":[true,null],"b":1}')
        with self.assertRaises(ValueError):
            jcs({"ratio": 0.5})


class LogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.signer = LogSigner.from_seed(SEED_A)
        self.genesis = create_genesis(genesis_state(self.signer), self.signer, version_time=T1)
        self.did = self.genesis["state"]["id"]

    def test_scid_is_self_certifying(self) -> None:
        verified = verify_log([self.genesis])
        self.assertEqual(verified.did, self.did)
        self.assertTrue(self.did.startswith("did:content:zQm"))
        self.assertEqual(self.genesis["state"]["parties"][0]["id"], f"{self.did}#party-1")
        self.assertTrue(self.genesis["versionId"].startswith("1-"))

    def test_tampered_state_is_rejected(self) -> None:
        tampered = copy.deepcopy(self.genesis)
        tampered["state"]["content"]["locations"] = ["https://evil.example/x"]
        with self.assertRaisesRegex(DidContentError, "SCID does not match"):
            verify_log([tampered])

    def test_update_rotates_key_and_keeps_binding(self) -> None:
        new_signer = LogSigner.from_seed(SEED_B)
        state = copy.deepcopy(self.genesis["state"])
        state["content"]["locations"] = ["ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"]
        entry2 = append_entry(
            [self.genesis], state, self.signer, {"updateKeys": [new_signer.multikey]}, version_time=T2
        )
        state3 = copy.deepcopy(state)
        state3["content"]["hardBindings"].append({"digestMultibase": multihash_sha256(b"extra")})
        entry3 = append_entry([self.genesis, entry2], state3, new_signer, version_time=T3)
        verified = verify_log([self.genesis, entry2, entry3])
        self.assertEqual(verified.active_parameters["updateKeys"], [new_signer.multikey])
        result = resolve([self.genesis, entry2, entry3], version_id=entry2["versionId"])
        self.assertEqual(result["didDocumentMetadata"]["nextVersionId"], entry3["versionId"])
        self.assertEqual(resolve([self.genesis, entry2, entry3], version_time=T2)["didDocumentMetadata"]["versionId"], entry2["versionId"])

    def test_old_key_cannot_sign_after_rotation(self) -> None:
        new_signer = LogSigner.from_seed(SEED_B)
        entry2 = append_entry([self.genesis], self.genesis["state"], self.signer, {"updateKeys": [new_signer.multikey]}, version_time=T2)
        entry3 = append_entry([self.genesis, entry2], self.genesis["state"], self.signer, version_time=T3)
        with self.assertRaisesRegex(DidContentError, "not signed by an authorized updateKey"):
            verify_log([self.genesis, entry2, entry3])

    def test_removing_hard_binding_is_rejected(self) -> None:
        state = copy.deepcopy(self.genesis["state"])
        state["content"]["hardBindings"] = [{"digestMultibase": multihash_sha256(b"other")}]
        entry2 = append_entry([self.genesis], state, self.signer, version_time=T2)
        with self.assertRaisesRegex(DidContentError, "hard bindings may not be removed"):
            verify_log([self.genesis, entry2])

    def test_pre_rotation_enforced(self) -> None:
        next_signer = LogSigner.from_seed(SEED_B)
        genesis = create_genesis(
            genesis_state(self.signer), self.signer, version_time=T1,
            next_key_hashes=[multikey_hash(next_signer.multikey)],
        )
        stranger = LogSigner.generate()
        bad = append_entry([genesis], genesis["state"], self.signer,
                           {"updateKeys": [stranger.multikey], "nextKeyHashes": []}, version_time=T2)
        with self.assertRaisesRegex(DidContentError, "was not pre-rotated"):
            verify_log([genesis, bad])
        good = append_entry([genesis], genesis["state"], self.signer,
                            {"updateKeys": [next_signer.multikey], "nextKeyHashes": []}, version_time=T2)
        self.assertEqual(verify_log([genesis, good]).active_parameters["updateKeys"], [next_signer.multikey])

    def test_deactivation_is_terminal(self) -> None:
        entry2 = append_entry([self.genesis], self.genesis["state"], self.signer,
                              {"deactivated": True, "updateKeys": []}, version_time=T2)
        result = resolve([self.genesis, entry2])
        self.assertTrue(result["didDocumentMetadata"]["deactivated"])
        entry3 = append_entry([self.genesis, entry2], self.genesis["state"], self.signer, version_time=T3)
        with self.assertRaisesRegex(DidContentError, "already deactivated"):
            verify_log([self.genesis, entry2, entry3])

    def test_jsonl_roundtrip(self) -> None:
        text = dump_log([self.genesis])
        self.assertEqual(len(text.strip().splitlines()), 1)
        self.assertEqual(load_log(text), [json.loads(text)])
        verify_log(load_log(text))


if __name__ == "__main__":
    unittest.main()
