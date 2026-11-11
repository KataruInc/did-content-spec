# The `did:content` DID Method

**Version:** 0.2 (draft) · **Published:** 2026-11-11 · **Supersedes:** 0.1 (2023-07-28)

`did:content` is registered in the W3C DID Method Registry
([DID Extensions: Methods](https://www.w3.org/TR/did-extensions-methods/)).

| | |
|---|---|
| Method name | `content` |
| Status | Draft. Breaking changes from v0.1, see [Migration](#13-migration-from-v01). |
| Reference implementation | [`app/`](app/) (Python, `cryptography` only) |
| Test vectors | [`examples/`](examples/) |
| JSON-LD context | [`contexts/did-content-v1.jsonld`](contexts/did-content-v1.jsonld) |
| JSON Schema (log entry) | [`schemas/log-entry.schema.json`](schemas/log-entry.schema.json) |
| Design rationale | [`docs/design-rationale.md`](docs/design-rationale.md) |
| Interoperability guide | [`docs/interoperability.md`](docs/interoperability.md) |

## Abstract

`did:content` identifies a piece of digital content (an image, a video, a sound
recording, a text, a model file, a dataset…) rather than a person or an
organisation. The identifier is **self-certifying**: it is derived from a hash
of the content and of the keys that control it, so it can be verified without
trusting the server that served it. A **DID Log** records every change to the
DID document as a hash-chained, signed history, which lets a resolver prove
*who* controlled the content at *which time*, and lets the controller move the
bytes between storages, rotate keys, add rights holders and publish
machine-readable licence terms (including AI-training permissions) without
changing the identifier.

The method is designed to sit next to, not compete with, the content
provenance stack that emerged in 2024–2026: C2PA Content Credentials, CAWG
identity assertions, ISCC (ISO 24138), RSL and on-chain IP registries. A
`did:content` DID is the stable, resolvable *subject* that those systems can
point at.

## Status of this document

This is an editor's draft maintained by Kataru Inc. Comments are welcome as
GitHub issues. The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, MAY
are to be interpreted as described in RFC 2119 / RFC 8174.

The method conforms to [Decentralized Identifiers (DIDs) v1.1](https://www.w3.org/TR/did-1.1/),
[Controlled Identifiers v1.0](https://www.w3.org/TR/cid-1.0/),
[DID Resolution v0.3](https://www.w3.org/TR/did-resolution/) and
[Verifiable Credential Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/).

---

## 1. Introduction and motivation

Content on the Internet is identified by where it is stored (an S3 key, a
YouTube URL, a CDN path). When the storage moves, the identifier breaks; when
the platform changes its rules, the creator's rights go with it. Meanwhile,
since 2024 the industry has converged on three separate questions that all
need a *stable identifier for the content itself*:

1. **Provenance** — "where did these bytes come from?" C2PA Content Credentials
   are now written by cameras (Leica, Sony, Nikon, Canon, Google Pixel 10),
   preserved by CDNs (Cloudflare) and surfaced by platforms (Google Search,
   YouTube, LinkedIn, TikTok). The EU AI Act Article 50 transparency
   obligations (enforced from 2 August 2026) make machine-readable provenance
   a legal requirement for generated media.
2. **Identity of the parties** — "who made it, who owns it?" C2PA 2.x removed
   creator identity from the core spec; the CAWG identity assertion (now at
   DIF) puts it back using X.509 or W3C Verifiable Credentials, and news
   publishers verify themselves through IPTC's Verified News Publisher list.
3. **Rights and AI usage terms** — "what may a machine do with it, and who gets
   paid?" RSL 1.0 (Reddit, Yahoo, Medium…), Cloudflare Content Signals,
   W3C TDMRep and on-chain registries such as Story's IP Asset Registry
   (200k+ registrations in 2025) all express licensing terms, but each in its
   own silo.

`did:content` provides the missing piece: a decentralised, verifiable,
storage-independent identifier for a content item that carries (a) hard and
soft bindings to the bytes, (b) the DIDs of the parties and their roles, (c)
licence and royalty terms in the vocabularies the ecosystem already uses, and
(d) a verifiable history of all of the above.

### 1.1 Design principles

- **Self-certifying.** The DID is a hash of its genesis state. Any copy of the
  DID Log, from any server, can be verified offline.
- **Content-bound but updatable.** The content hash is fixed at creation and
  can never be removed; everything else (locations, keys, parties, licence) can
  change through signed log entries.
- **Boring cryptography.** Multikey, multihash, JCS (RFC 8785) and the W3C
  Data Integrity `eddsa-jcs-2022` cryptosuite. No custom signature formats.
- **Transport-agnostic.** The DID Log is a plain JSON Lines file. It can be
  served over HTTPS, pinned on IPFS, mirrored by many registries or embedded in
  a C2PA manifest.
- **Reuse, don't reinvent.** Roles follow CAWG; usage/payment tokens follow
  RSL; soft bindings follow the C2PA soft-binding algorithm list; the log
  format follows `did:webvh`.
- **No PII in the document.** Parties and payees are DIDs and payment URIs,
  never names or e-mail addresses.

---

## 2. Terminology

| Term | Meaning |
|---|---|
| **Content** | The byte sequence identified by the DID (one file / one encoding). A re-encoding or edit is *different content* and gets its own DID that links back via `derivedFrom`. |
| **SCID** | Self-Certifying Identifier: the method-specific identifier, a multibase/multihash of the genesis log entry. |
| **DID Log** | The ordered list of log entries (`did.jsonl`) that fully describes the DID from creation to its current (or deactivated) state. |
| **Log entry** | One version of the DID: `versionId`, `versionTime`, `parameters`, `state` (the DID document) and `proof`. |
| **Update key** | A Multikey-encoded public key listed in `parameters.updateKeys`, authorised to sign the *next* log entry. |
| **Registry** | Any HTTPS server, IPFS node or other store that serves a DID Log. Registries are untrusted: resolvers verify everything. |
| **Hard binding** | A cryptographic hash of the exact bytes (multihash). |
| **Soft binding** | A perceptual fingerprint or watermark (e.g. ISCC) that survives re-encoding; used for lookup, never for proof of integrity. |
| **Party** | A DID that holds a role (creator, rights holder, publisher…) with respect to the content. |

---

## 3. Method syntax

### 3.1 ABNF

```abnf
did-content   = "did:content:" scid
scid          = "z" 1*base58char          ; multibase(base58btc, multihash(...))
base58char    = %x31-39 / %x41-48 / %x4A-4E / %x50-5A / %x61-6B / %x6D-7A
                ; Bitcoin base58 alphabet (no 0, O, I, l)
```

The SCID is a [multibase](https://datatracker.ietf.org/doc/draft-multiformats-multibase/)
(base58btc, prefix `z`) encoding of a
[multihash](https://datatracker.ietf.org/doc/draft-multiformats-multihash/) of
the canonicalised genesis log entry (§5.4). Because the multihash is
self-describing, future hash algorithms can be introduced without changing the
syntax. In this version the hash algorithm MUST be `sha2-256` (multihash code
`0x12`), so every v0.2 identifier starts with `did:content:zQm`.

Example (from [`examples/did.jsonl`](examples/did.jsonl)):

```
did:content:zQmbnKX58u9eGUuDCDjKxCaG48Xr375dvf81vdGZqz31ze4
```

### 3.2 DID URLs

`did:content` DID URLs support the generic DID URL syntax and the following
DID URL parameters from DID Resolution v0.3:

| Parameter | Meaning |
|---|---|
| `versionId` | Resolve the DID document at the given log `versionId` (e.g. `?versionId=2-zQm...`). |
| `versionTime` | Resolve the document that was current at the given RFC 3339 time. |
| `service` / `relativeRef` | Dereference a service endpoint (e.g. `?service=delivery`). |

Fragments identify resources *inside* the DID document: verification methods
(`#key-1`), parties (`#party-1`), licences (`#license-1`) and services
(`#delivery`). The v0.1 pseudo-fragments `#author` and `#rights-holder` are
deprecated; use `parties` with `role` instead (§4.3).

### 3.3 Legacy (v0.1) identifiers

Identifiers created under v0.1 are 55 base58 characters and never start with
`z`. Resolvers MAY recognise them and resolve them through a v0.1 resolver,
but MUST NOT treat them as self-certifying. New identifiers MUST use the v0.2
syntax. See [Migration](#13-migration-from-v01).

---

## 4. DID document data model

A `did:content` DID document is the `state` of a log entry. It MUST be a JSON
object conforming to DID Core 1.1 and MAY be processed as JSON-LD using the
contexts below. Producers SHOULD include:

```json
"@context": [
  "https://www.w3.org/ns/did/v1.1",
  "https://did.kataru.io/did-content/v1"
]
```

The canonical copy of the second context is
[`contexts/did-content-v1.jsonld`](contexts/did-content-v1.jsonld).

### 4.1 Core properties

| Property | Requirement | Notes |
|---|---|---|
| `id` | REQUIRED | The DID. Immutable across versions. |
| `controller` | RECOMMENDED | DIDs (not fragments) of the entities allowed to act for the content, e.g. `did:key`, `did:web`, `did:webvh`, `did:plc`. Must not contain `did:content` fragments. |
| `alsoKnownAs` | OPTIONAL | Other identifiers of *the same content*: an ISCC (`ISCC:…`), an ISRC/ISWC URN, a Story IP Asset URL, a C2PA instance ID, etc. |
| `verificationMethod` | OPTIONAL | `Multikey` (RECOMMENDED) or `JsonWebKey` entries per Controlled Identifiers v1.0. Used for assertions *about* the content (e.g. signing a Verifiable Credential whose subject is the DID). |
| `authentication`, `assertionMethod`, `capabilityInvocation`, `capabilityDelegation`, `keyAgreement` | OPTIONAL | Standard verification relationships. The v0.1 property `updation` is removed; the right to update the DID is expressed by `parameters.updateKeys` in the log (§5.2), not by the document. |
| `service` | OPTIONAL | See §4.6. |

### 4.2 `content` (REQUIRED)

Binds the DID to the bytes.

```json
"content": {
  "mediaType": "image/png",
  "byteLength": 165,
  "hardBindings": [
    { "digestMultibase": "zQmQoJLz2eqTpNQ7qjqTQ8bJNd24uUaH3YnHXRVmyjn4S7x" }
  ],
  "softBindings": [
    { "alg": "io.iscc.v0", "value": "ISCC:…" }
  ],
  "locations": [
    "ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
    "https://cdn.example.com/sample.png"
  ]
}
```

| Field | Requirement | Rules |
|---|---|---|
| `mediaType` | REQUIRED | IANA media type of the bytes. |
| `byteLength` | RECOMMENDED | Length in bytes. |
| `hardBindings[]` | REQUIRED (≥ 1) | Each entry has `digestMultibase`: multibase(base58btc) of a multihash of the *exact* bytes. `sha2-256` is REQUIRED to be supported; additional algorithms (e.g. `blake3`, `sha3-256`) MAY be added. **Hard bindings MUST NOT be removed or altered in later versions**; they MAY be appended (e.g. to add a second algorithm). The genesis entry MUST contain at least one. |
| `softBindings[]` | OPTIONAL | `alg` MUST be an identifier from the [C2PA soft-binding algorithm list](https://github.com/c2pa-org/softbinding-algorithm-list) (e.g. `io.iscc.v0` for ISO 24138 ISCC). `value` is the algorithm's native string form. Soft bindings are hints for lookup (§7.4) and MUST NOT be used to prove integrity. |
| `locations[]` | OPTIONAL | URLs from which the bytes can be fetched (`https:`, `ipfs:`, `ar:`, `s3:`…). Order is preference order. Clients MUST verify fetched bytes against `hardBindings`. |

A client that obtains bytes from *any* source and finds a matching hard
binding has verified that the bytes are the content identified by the DID.
This is what makes storage interchangeable.

### 4.3 `parties` (RECOMMENDED)

Who stands in which relationship to the content. Replaces the v0.1
`#author` / `#rights-holder` fragments.

```json
"parties": [
  { "id": "did:content:zQm…#party-1", "role": "creator",      "party": "did:key:z6Mk…" },
  { "id": "did:content:zQm…#party-2", "role": "rightsHolder", "party": "did:web:label.example.com" }
]
```

`party` MUST be a DID (or a DID URL). `role` MUST be one of the following
tokens, which map 1:1 to the CAWG identity-assertion role vocabulary where one
exists:

| `role` | CAWG `role` | Meaning |
|---|---|---|
| `creator` | `cawg.creator` | Primary author / performer / photographer |
| `contributor` | `cawg.contributor` | Secondary author |
| `editor` | `cawg.editor` | Edited or post-processed the content |
| `producer` | `cawg.producer` | Produced the content |
| `publisher` | `cawg.publisher` | Published / distributed the content |
| `sponsor` | `cawg.sponsor` | Commissioned or sponsored the content |
| `translator` | `cawg.translator` | Adapted from another language |
| `rightsHolder` | — | Holds the exploitation rights (may differ from the creator) |
| `licensor` | — | Entitled to grant licences (defaults to `rightsHolder`) |
| `generator` | — | The AI system / provider that generated the content (for EU AI Act Art. 50 disclosure). Use with `provenance`. |

Names, e-mail addresses or other PII MUST NOT be placed in `parties`. Human-
readable attribution belongs in a Verifiable Credential or a C2PA/CAWG
assertion referenced from `provenance`.

### 4.4 `license` (OPTIONAL) and `royalty` (OPTIONAL)

Machine-readable terms. Several licences MAY coexist (e.g. a free
attribution licence for search and a paid licence for AI training).

```json
"license": [
  {
    "id": "did:content:zQm…#license-1",
    "type": "RSLLicense",
    "permits":   { "usage": ["search"], "user": ["commercial", "non-commercial"] },
    "prohibits": { "usage": ["ai-train", "ai-input"] },
    "payment":   { "type": "attribution" },
    "terms": "https://label.example.com/licenses/standard"
  },
  {
    "id": "did:content:zQm…#license-2",
    "type": "RSLLicense",
    "permits": { "usage": ["ai-train"], "user": ["commercial"] },
    "payment": { "type": "training", "terms": "https://label.example.com/licenses/ai-training" }
  }
],
"royalty": {
  "recipients": [
    { "party": "did:content:zQm…#party-1", "shareBasisPoints": 8000, "payTo": "did:pkh:eip155:1:0x…" },
    { "party": "did:content:zQm…#party-2", "shareBasisPoints": 2000, "payTo": "payto:iban/DE75…" }
  ]
}
```

| Field | Rules |
|---|---|
| `license[].type` | `RSLLicense` (terms expressed with the RSL 1.0 vocabulary, below), `CreativeCommons` (`terms` is the CC deed URL), `SPDX` (`terms` is an SPDX licence URL), `PIL` (Story Programmable IP License; `terms` is the license-terms URL/ID), or `Custom` (`terms` REQUIRED). |
| `permits` / `prohibits` | Objects with `usage[]`, `user[]`, `geo[]` using the RSL 1.0 tokens. `usage`: `all`, `ai-all`, `ai-train`, `ai-input`, `ai-index`, `search`. `user`: `commercial`, `non-commercial`, `education`, `government`, `personal`. `geo`: ISO 3166-1 alpha-2. |
| `payment.type` | RSL 1.0 tokens: `free`, `purchase`, `subscription`, `training`, `crawl`, `use`, `contribution`, `attribution`. |
| `terms` | URL of the full legal text or of an external licence record. |
| `royalty.recipients[].party` | Fragment reference to a `parties` entry. |
| `royalty.recipients[].shareBasisPoints` | Integer 0–10000. The sum over all recipients SHOULD be 10000. Integers are used because the document is JCS-canonicalised; floats are forbidden. |
| `royalty.recipients[].payTo` | A payment pointer URI: `did:pkh:…` (blockchain account), `payto:` (RFC 8905), Open Payments `https://` pointer, `lightning:`… **E-mail addresses MUST NOT be used** (they are PII and are not payment endpoints). |

If no `license` is present, nothing is granted; crawlers and AI systems
SHOULD treat the content as "all rights reserved", consistent with TDMRep's
reservation semantics.

### 4.5 `provenance` and `derivedFrom` (OPTIONAL)

```json
"provenance": [
  { "type": "C2PAManifest", "digestMultibase": "zQm…", "url": "https://cdn.example.com/sample.png" },
  { "type": "VerifiableCredential", "url": "https://issuer.example/credentials/42" }
],
"derivedFrom": ["did:content:zQmParent…"]
```

- `provenance[]` points to external provenance records about this content: a
  C2PA manifest (embedded in the asset at `url` or served separately), a
  CAWG identity assertion, a Verifiable Credential (e.g. an IPTC-verified
  publisher credential), or an on-chain registration. `digestMultibase` is
  RECOMMENDED so the record can be verified.
- `derivedFrom[]` lists the `did:content` DIDs this content was derived from
  (crop, remix, translation, AI generation using the parent as input). This
  gives a verifiable derivative graph comparable to on-chain IP registries,
  without requiring a chain.

### 4.6 Services

| `type` | Purpose |
|---|---|
| `ContentDelivery` | Endpoint that serves the bytes (may require authorisation). Equivalent to `content.locations` but allows richer service descriptions. |
| `LicenseNegotiation` | Endpoint (e.g. an RSL licence server or a pay-per-crawl endpoint) where a licence in `license[]` can be purchased. |
| `ProvenanceLookup` | Endpoint that returns C2PA manifests / credentials for this content. |
| `DIDContentLog` | Alternative registry URL(s) of the DID Log itself. |

Service `id`s MUST be DID URL fragments of this DID.

---

## 5. The DID Log

The DID Log format is adapted from
[`did:webvh` 1.0](https://identity.foundation/didwebvh/v1.0/) (DIF, August
2025): a JSON Lines file, one entry per version, each entry hash-chained to the
previous one and signed by an authorised update key.

### 5.1 Log entry

```json
{
  "versionId":   "2-zQm…",
  "versionTime": "2026-11-10T00:00:00Z",
  "parameters":  { "updateKeys": ["z6Mk…"], "nextKeyHashes": [] },
  "state":       { "...": "the DID document (§4)" },
  "proof":       [ { "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "...": "..." } ]
}
```

| Field | Rules |
|---|---|
| `versionId` | `<n>-<entryHash>` where `n` is the 1-based version number and `entryHash` is computed as in §5.3. |
| `versionTime` | RFC 3339 UTC timestamp. MUST be ≥ the previous entry's and MUST NOT be in the future (resolvers allow 5 minutes of clock skew). |
| `parameters` | Changes to the method parameters (§5.2). Unchanged parameters are inherited from the previous entry. |
| `state` | The complete DID document for this version. |
| `proof` | Array of Data Integrity proofs (§5.5). At least one MUST verify against an authorised update key. |

The full entry including `versionId` (but excluding `proof`) is what is
signed.

### 5.2 Parameters

| Parameter | First entry | Later entries | Meaning |
|---|---|---|---|
| `method` | REQUIRED, `"did:content:0.2"` | MAY (only to upgrade) | Method/version of the log format. Resolvers MUST reject unknown values. |
| `scid` | REQUIRED | MUST NOT appear | The SCID (§5.4). |
| `updateKeys` | REQUIRED, ≥ 1 | OPTIONAL (REQUIRED when pre-rotation is active) | Multikey public keys authorised to sign the **next** entry. The first entry is signed by its own `updateKeys`. |
| `nextKeyHashes` | OPTIONAL | OPTIONAL | Key pre-rotation (§5.6): multihashes (as `multihash_sha256(multikey string)`) of the keys that are allowed to appear in the next `updateKeys`. |
| `witness` | OPTIONAL | OPTIONAL | `{ "threshold": n, "witnesses": [ { "id": "did:key:…" } ] }`. See §5.7. |
| `watchers` | OPTIONAL | OPTIONAL | URLs of services that mirror and monitor the log. |
| `registries` | OPTIONAL | OPTIONAL | Base URLs of registries where the log is published (§7.1). |
| `ttl` | OPTIONAL (default 3600) | OPTIONAL | Seconds a resolver may cache the resolution result. |
| `deactivated` | — | OPTIONAL | `true` ends the log (§6.4). |

### 5.3 Entry hash

```
preimage  = entry without "proof", with "versionId" replaced by the previous entry's versionId
            (for the first entry: replaced by the SCID)
entryHash = multibase_base58btc( multihash_sha2-256( JCS(preimage) ) )
versionId = n + "-" + entryHash
```

JCS is RFC 8785. Documents MUST NOT contain floating-point numbers.

### 5.4 SCID generation (Create)

1. Build the first entry with the literal string `{SCID}` wherever the SCID
   will appear: `versionId`, `parameters.scid`, `state.id` and every DID URL
   inside `state` (party ids, service ids, verification method ids…). The
   placeholder MUST NOT remain anywhere after step 3.
2. `scid = multibase_base58btc( multihash_sha2-256( JCS(preliminary entry) ) )`.
3. Replace every occurrence of `{SCID}` with `scid`.
4. Compute the entry hash (§5.3) with the SCID as the "previous versionId" and
   set `versionId = "1-" + entryHash`.
5. Sign (§5.5).

Because `state.content.hardBindings` is part of the hashed genesis entry, the
SCID commits to the content bytes as well as to the initial keys and parties.

### 5.5 Proofs

Each proof MUST be a `DataIntegrityProof` with `cryptosuite`
`eddsa-jcs-2022` (REQUIRED to support) or `ecdsa-jcs-2019` (OPTIONAL),
`proofPurpose` `assertionMethod`, and a `verificationMethod` of the form
`did:key:<multikey>#<multikey>` where `<multikey>` is one of the authorised
update keys. For the first entry the authorised keys are its own
`updateKeys`; for entry *n* > 1 they are the `updateKeys` active after entry
*n − 1*.

### 5.6 Key pre-rotation

If the active parameters contain a non-empty `nextKeyHashes`, then the next
entry MUST explicitly include both `updateKeys` and `nextKeyHashes`, and the
hash of every key in the new `updateKeys` MUST be present in the previous
`nextKeyHashes`. This limits the damage of a compromised update key: an
attacker cannot rotate to a key of their choosing. Pre-rotation is
RECOMMENDED for all production DIDs.

### 5.7 Witnesses

When `witness.threshold` > 0, an entry MUST NOT be considered valid unless at
least `threshold` witness proofs over the entry's `versionId` are available,
either inline in `proof` (signed by witness keys) or in a sibling
`did-witness.json` file with the structure defined by `did:webvh` 1.0.
Witnesses protect against a registry or a compromised controller rewriting
history. Verification of witness proofs is not yet implemented in the
reference implementation.

---

## 6. DID operations

### 6.1 Create

1. Compute the hard binding(s) of the content bytes.
2. Generate (or choose) one or more update keys. Optionally prepare
   pre-rotation keys and compute `nextKeyHashes`.
3. Build the genesis `state` (§4) and parameters (§5.2) and derive the SCID
   (§5.4). Sign the entry.
4. Publish the one-line `did.jsonl` to one or more registries (§7) and,
   optionally, embed the DID into the content's C2PA manifest and into the
   HTTP `Link` header of the content URL (§7.2).

Creation needs no permission from any party: the DID exists as soon as the
genesis entry exists.

### 6.2 Read (Resolve)

Input: a `did:content` DID, optional `versionId` / `versionTime`.

1. Locate the DID Log (§7.1). If several copies are obtained, use the longest
   one that verifies; conflicting valid forks are a security event (§10).
2. Verify the log:
   1. First entry: `method` is supported; recompute the SCID (§5.4) and
      compare with `parameters.scid` and the DID.
   2. For each entry: version numbers are consecutive from 1; `entryHash`
      matches (§5.3); `versionTime` is monotonic and not in the future; `scid`
      appears only in entry 1.
   3. Verify at least one proof per entry against the authorised update keys
      (§5.5) and enforce pre-rotation (§5.6) and witnesses (§5.7).
   4. `state.id` equals the DID in every entry; hard bindings are never
      removed or altered; no entry follows a `deactivated: true` entry; a
      deactivating entry sets `updateKeys` to `[]`.
3. Select the requested version (default: last) and return a DID Resolution
   result:

```json
{
  "@context": "https://w3id.org/did-resolution/v1",
  "didDocument": { "...": "state of the selected entry" },
  "didDocumentMetadata": {
    "created": "2026-11-01T00:00:00Z",
    "updated": "2026-11-10T00:00:00Z",
    "versionId": "2-zQm…",
    "deactivated": false,
    "nextVersionId": "…", "nextUpdate": "…"
  },
  "didResolutionMetadata": { "contentType": "application/did" }
}
```

Errors use the DID Resolution error vocabulary (`invalidDid`, `notFound`,
`invalidDidDocument`, `methodNotSupported`…). A log that fails any check MUST
produce `invalidDidDocument`; a resolver MUST NOT fall back to an unverified
copy.

Full algorithm: [`app/didcontent/log.py`](app/didcontent/log.py) `verify_log` / `resolve`.

### 6.3 Update

Append an entry (§5.1) containing the full new `state` and any changed
parameters, signed by a currently authorised update key. Typical updates:

- move or add `content.locations` (storage migration, IPFS pinning);
- rotate `updateKeys` (optionally through pre-rotation);
- add parties, licences, royalty splits, provenance records;
- change services.

The following MUST NOT change: `state.id`, existing `content.hardBindings`.
A change to the bytes is a *new DID* with `derivedFrom` pointing at the old
one.

### 6.4 Deactivate

Append an entry with `parameters.deactivated: true` and
`parameters.updateKeys: []` (and `nextKeyHashes: []` if pre-rotation was
active). The log is then closed; resolvers return the final document with
`didDocumentMetadata.deactivated: true`. The content bytes are unaffected.
Registries SHOULD keep deactivated logs available so that historical
verification stays possible.

---

## 7. Registries, discovery and transport

Registries are untrusted mirrors; the method relies on verification, not on
the registry's honesty. This is the main difference from a centralised
resolver database (v0.1) and from `did:web`.

### 7.1 Locating the log

A resolver SHOULD try, in order, until a verifiable log is found:

1. Registries named in the resolver's configuration (e.g. a Universal
   Resolver driver configured with `https://did.kataru.io`).
2. Registries named in a previously cached copy of the log
   (`parameters.registries`, `parameters.watchers`).
3. A `DIDContentLog` service in a cached document.

For an HTTPS registry with base URL `B`, the log is served at

```
GET {B}/.well-known/did-content/{scid}/did.jsonl       → application/jsonl
GET {B}/.well-known/did-content/{scid}/did-witness.json (if witnesses are used)
GET {B}/1.0/identifiers/{did}                           → DID Resolution result (HTTPS binding)
```

A registry MAY also serve the log from IPFS/IPNS; `ipfs://<cid>` of the log
file is a valid location for an immutable snapshot.

### 7.2 Advertising the DID from the content

- **HTTP:** servers SHOULD send `Link: <did:content:zQm…>; rel="describedby"`
  with the content, and MAY send the RSL `Link: <…>; rel="license";
  type="application/rsl+xml"` for the same terms.
- **C2PA:** manifests SHOULD carry the DID in a `cawg.identity` assertion
  (as the named actor's DID-based credential) or in a custom assertion
  labelled `io.kataru.did_content` whose payload is `{ "did": "did:content:…"}`.
  Conversely the DID document's `provenance` references the manifest.
- **HTML:** `<link rel="describedby" href="did:content:zQm…">`.

### 7.3 Publishing (registry API)

Registries that accept submissions SHOULD expose:

```
PUT  {B}/.well-known/did-content/{scid}/did.jsonl   body: full log
```

and MUST verify the log (§6.2 step 2) before storing it. A registry MUST NOT
accept a log whose first entries differ from the copy it already holds (no
history rewriting) and SHOULD accept only logs that extend its copy.

### 7.4 Reverse lookup (bytes → DID)

Because the content is identified by its hash, a registry SHOULD support
lookup from the content side, which is the operation CDNs, platforms and
crawlers actually need:

```
GET {B}/1.0/lookup?digestMultibase=zQm…         → list of DIDs with that hard binding
GET {B}/1.0/lookup?softBinding=io.iscc.v0:ISCC:… → list of DIDs with a near-matching soft binding
```

Hard-binding results are authoritative (the resolver re-verifies). Soft-
binding results are candidates only.

---

## 8. Interoperability

Summary; details and mappings in [`docs/interoperability.md`](docs/interoperability.md).

| Ecosystem | Relationship to `did:content` |
|---|---|
| **C2PA Content Credentials 2.x** | C2PA answers "how was this asset produced"; `did:content` gives the asset a resolvable identity. Hard binding ≡ C2PA hard binding; `softBindings.alg` uses the C2PA registry; `provenance` points at the manifest; the manifest points at the DID. |
| **CAWG identity assertion** | `parties[].role` tokens map to `cawg.*` roles; a party DID can be the named actor; an identity-claims-aggregation VC can be listed in `provenance`. |
| **ISCC (ISO 24138:2024)** | ISCC is a *similarity* identifier; `did:content` is an *exact, controllable* identifier. Put the ISCC in `softBindings` (`io.iscc.v0`) and `alsoKnownAs`. |
| **RSL 1.0 / Content Signals / TDMRep** | `license[]` reuses RSL usage, user and payment tokens so one declaration can be rendered as RSL XML, robots.txt Content-Signal lines or TDMRep headers. |
| **Story / on-chain IP registries** | `alsoKnownAs` carries the IP Asset identifier; `license[].type: "PIL"` references PIL terms; `derivedFrom` mirrors the derivative graph; `payTo` uses `did:pkh`. |
| **W3C VC 2.0** | A `did:content` DID is a valid `credentialSubject.id`; document keys (`assertionMethod`) can sign credentials about the content. |
| **Universal Resolver / DID Resolution** | The HTTPS binding and result format are those of DID Resolution v0.3, so a driver is a thin wrapper around `verify_log`. |
| **Music / publishing identifiers** | ISRC, ISWC, ISBN, EIDR, DOI go in `alsoKnownAs` as URNs; they identify *works/recordings*, `did:content` identifies *this file*. |

---

## 9. Reference implementation and test vectors

```
cd app
python3 -m unittest discover -s tests          # 11 tests
python3 content_did.py keygen --out key.hex
python3 content_did.py create --key key.hex --content photo.jpg --media-type image/jpeg \
        --location https://cdn.example/photo.jpg --out did.jsonl
python3 content_did.py verify did.jsonl
python3 content_did.py resolve did.jsonl --version-id 1-zQm…
python3 content_did.py check did.jsonl photo.jpg      # bytes ↔ hard binding
python3 make_examples.py                              # regenerates examples/
```

[`examples/`](examples/) contains a two-version log (`did.jsonl`), the
content it binds (`sample.png`), the current document and resolution results.
The keys used there are published test keys and MUST NOT be reused.

Requirements: Python ≥ 3.10 and the `cryptography` package.

---

## 10. Security considerations

- **Self-certification.** The DID commits to the genesis entry; the entry
  hash chain commits to every later version. A registry cannot alter history
  without detection. A resolver that accepts an unverified log is
  non-conformant.
- **Key compromise.** An attacker with an active update key can append
  entries. Mitigations: pre-rotation (§5.6) prevents rotation to attacker-
  chosen keys; witnesses (§5.7) require independent approval; `watchers`
  and multiple registries make silent forks visible. Controllers SHOULD keep
  update keys separate from document keys and offline where possible.
- **Forks and withholding.** A malicious controller or registry may publish
  two valid logs, or an old one. Resolvers SHOULD query more than one source,
  prefer the longest valid chain, and treat conflicting chains at the same
  version as a compromise indicator. Witness thresholds eliminate the attack
  for DIDs that opt in.
- **Content substitution.** Locations are untrusted; clients MUST compare
  fetched bytes with `hardBindings`. Soft bindings are never sufficient.
- **Hash agility.** multihash makes the algorithm explicit. Resolvers MUST
  reject algorithms they do not support rather than skip the check.
- **Canonicalisation.** JCS has no floats or duplicate keys in this profile.
  Implementations MUST reject documents with floats or duplicate keys.
- **Clock.** `versionTime` is controller-asserted. Resolvers reject future
  timestamps but cannot prove past ones; use witnesses or an external
  timestamp (e.g. a chain anchor listed in `provenance`) when time matters
  legally.
- **Denial of service.** Logs are small; registries SHOULD cap entry size and
  rate-limit `PUT`.
- **Legacy identifiers** are not self-certifying and inherit the security
  properties of the v0.1 resolver that serves them.

## 11. Privacy considerations

- The DID document MUST NOT contain names, e-mail addresses, postal
  addresses, phone numbers or other direct PII. Parties are DIDs; payees are
  payment URIs. (v0.1's e-mail-based `royaltyRecipients` is withdrawn for this
  reason.)
- Payment URIs and party DIDs are pseudonymous but linkable. Controllers who
  need unlinkability SHOULD use per-content `did:key` parties and payment
  pointers, and keep the mapping off-document.
- The log is a permanent public history. Information that may need to be
  withdrawn later (e.g. a licensee's DID) belongs in a revocable credential
  referenced from `provenance`, not in the document.
- Deactivation does not delete history. Operators subject to erasure
  requests SHOULD design so that erasable data is never in the log.
- Soft bindings (perceptual hashes) can enable content matching across
  services; publishers that do not want this SHOULD omit `softBindings`.
- Resolution requests reveal interest in a content item to the registry;
  resolvers MAY batch or proxy requests, and logs MAY be mirrored on IPFS.

---

## 12. Conformance

An implementation is a conforming **producer** if every log it emits verifies
under §6.2. An implementation is a conforming **resolver** if it performs
every check in §6.2 and returns results in the DID Resolution format. A
conforming **registry** performs the checks of §7.3.

## 13. Migration from v0.1

| v0.1 | v0.2 |
|---|---|
| `Base58(RIPEMD160(sha3-256(doc)))` of the whole document (changed on every update) | SCID of the genesis entry; stable across updates |
| Central resolver database maps DID → storage location | Self-verifying log; registries are untrusted mirrors |
| `controller` pointed at `#author` / `#rights-holder` fragments | `controller` = DIDs; roles in `parties` |
| `updation` relationship | `parameters.updateKeys` (+ pre-rotation) |
| `EcdsaSecp256k1RecoveryMethod2020`, ad-hoc `"proof": {"type": "Secp256k1"}` | `Multikey`, `DataIntegrityProof` / `eddsa-jcs-2022` |
| `royaltyRecipients` with e-mail and float ratios | `royalty.recipients` with party refs, basis points and payment URIs |
| No content binding in the document | `content.hardBindings` (REQUIRED), `softBindings`, `locations` |
| No licence model | `license[]` with RSL/TDMRep-compatible tokens |
| `/create`, `/update`, `/delete` resolver RPC | DID Log publishing; DID Resolution HTTPS binding |

Existing v0.1 DIDs cannot be converted in place because they are not hashes of
a genesis state. Operators SHOULD create a v0.2 DID for each content item,
list the v0.1 DID in `alsoKnownAs`, and keep the v0.1 resolver running
read-only for a deprecation period.

## 14. Change history

- **2026-11-11 — v0.2 draft.** Self-certifying identifiers, DID Log with
  verifiable history, content bindings, parties/licence/royalty model,
  Data Integrity proofs, DID Resolution alignment, interoperability with
  C2PA/CAWG/ISCC/RSL. See [`CHANGELOG.md`](CHANGELOG.md).
- **2023-07-28 — v0.1 alpha.**

## Copyright

© 2023–2026 Mizuki Sonoko / Kataru Inc. All rights reserved until a licence
is chosen; the W3C Document License is recommended for the specification text
and a permissive OSS licence for `app/`.
