#!/usr/bin/env python3

# LEGACY (did:content v0.1, 2023). Kept only so that v0.1 identifiers can be
# recognised. New identifiers MUST be generated with content_did.py (v0.2).
# Note: this script base58-encodes the *hex string* of the RIPEMD-160 digest,
# which is why v0.1 identifiers are 55 characters long.
# Copyright (C) 2023 MizukiSonoko All Rights Reserved.

import base58
import hashlib

def create_did_from_did_doc(filepath: str) -> str:
  # Open docs
  doc_file = open(filepath, 'r')
  did_data = doc_file.read()
  doc_file.close()
  return create_did_from_did_doc_data(did_data.encode('utf-8'))

def create_did_from_did_doc_data(did_data: bytes) -> str:

  # sha3-256 hash
  sha3_hashed = hashlib.sha3_256(did_data).digest()

  # RIPEMD-160
  h = hashlib.new('ripemd160')
  h.update(sha3_hashed)
  ripemd160_hashed = h.hexdigest()

  # Convert Base58
  base58_encoded = base58.b58encode(ripemd160_hashed)

  print("did:content:{}".format(base58_encoded.decode()))

if __name__ == "__main__":
  create_did_from_did_doc('did-doc')
