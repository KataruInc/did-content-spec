#!/usr/bin/env python3

# Copyright (C) 2023 MizukiSonoko All Rights Rserved.

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
