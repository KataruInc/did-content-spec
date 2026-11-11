# Changelog

## 0.2 (draft) — 2026-11-11

### Identifier
- **Breaking.** The method-specific identifier is now a Self-Certifying Identifier
  (multibase base58btc of a sha2-256 multihash of the canonicalised genesis log
  entry). Identifiers are stable across updates and start with `zQm`.
- v0.1 identifiers (55 chars, base58 of the *hex string* of
  RIPEMD160(sha3-256(doc))) are recognised as legacy only.

### Data model
- Added `content` (REQUIRED): `mediaType`, `byteLength`, `hardBindings[]`
  (`digestMultibase`), `softBindings[]` (C2PA soft-binding `alg` ids such as
  `io.iscc.v0`), `locations[]`.
- Added `parties[]` with a CAWG-aligned `role` vocabulary; removed the
  `#author` / `#rights-holder` pseudo-fragments.
- Added `license[]` using RSL 1.0 usage/user/payment tokens, plus
  `CreativeCommons`, `SPDX`, `PIL` and `Custom` types.
- Replaced `royaltyRecipients` (e-mail + float ratio) with `royalty.recipients`
  (party reference, basis points, payment URI). E-mail addresses are forbidden.
- Added `provenance[]` and `derivedFrom[]`.
- Removed the non-standard `updation` relationship and the custom
  `"proof": {"type": "Secp256k1"}` object. Verification methods use `Multikey`.
- Defined service types `ContentDelivery`, `LicenseNegotiation`,
  `ProvenanceLookup`, `DIDContentLog`.
- New JSON-LD context `https://did.kataru.io/did-content/v1`
  (`contexts/did-content-v1.jsonld`) and JSON Schema for log entries.

### Operations
- Introduced the DID Log (`did.jsonl`) modelled on did:webvh 1.0: hash-chained
  entries, `updateKeys`, key pre-rotation (`nextKeyHashes`), optional witnesses
  and watchers, `deactivated`.
- Proofs are W3C Data Integrity `DataIntegrityProof` / `eddsa-jcs-2022`.
- Resolution follows DID Resolution v0.3 (result format, metadata, errors,
  `versionId` / `versionTime`, HTTPS binding `/1.0/identifiers/{did}`).
- Registries are untrusted mirrors; added well-known log location, `PUT`
  publishing rules, HTTP `Link` advertisement and reverse lookup
  (`/1.0/lookup?digestMultibase=` / `?softBinding=`).
- Removed the v0.1 `/create`, `/update`, `/delete` RPC endpoints.

### Documentation and tooling
- Rewrote security and privacy considerations.
- Added `docs/design-rationale.md` and `docs/interoperability.md`.
- Added the reference implementation `app/didcontent` with CLI
  `app/content_did.py`, unit tests and deterministic test vectors in
  `examples/`. `app/id_gen.py` is kept as legacy.

## 0.1 — 2023-07-28
- Initial alpha release.
