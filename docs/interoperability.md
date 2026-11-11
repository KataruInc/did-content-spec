# Interoperability guide

How a `did:content` DID document maps to, and is referenced from, the
provenance, identity and licensing systems that are in production in 2026.

## 1. C2PA Content Credentials

| C2PA concept | did:content |
|---|---|
| Hard binding (`c2pa.hash.data`, `c2pa.hash.bmff`) | `content.hardBindings[].digestMultibase` is a hash of the *whole file*. When a C2PA manifest is embedded, the file hash differs from the asset hash the manifest covers; record both: the embedded-file hash in `hardBindings`, the manifest in `provenance`. |
| Soft binding (`c2pa.soft-binding`, `alg`) | `content.softBindings[]` uses the same `alg` identifiers (e.g. `io.iscc.v0`). |
| Manifest | `provenance[] = { "type": "C2PAManifest", "digestMultibase": "<hash of the manifest store>", "url": "<asset or manifest URL>" }` |
| Referencing the DID from the manifest | Custom assertion label `io.kataru.did_content`, payload `{ "did": "did:content:zQm…", "versionId": "1-zQm…" }`; or the DID as the named actor in a `cawg.identity` assertion. |
| Manifest recovery when metadata is stripped | Registry reverse lookup (`/1.0/lookup?softBinding=io.iscc.v0:…`) returns candidate DIDs, whose `provenance` leads back to the manifest. |

## 2. CAWG identity assertion

- `parties[].role` ↔ `cawg.identity` `role`: `creator`→`cawg.creator`,
  `contributor`→`cawg.contributor`, `editor`→`cawg.editor`,
  `producer`→`cawg.producer`, `publisher`→`cawg.publisher`,
  `sponsor`→`cawg.sponsor`, `translator`→`cawg.translator`.
  `rightsHolder`, `licensor`, `generator` have no CAWG equivalent and are
  carried only in the DID document.
- A party DID (e.g. `did:web:label.example.com`) can be the *named actor*;
  an identity-claims-aggregation credential (`sig_type:
  cawg.identity_claims_aggregation`) that verifies that actor is listed in
  `provenance` as `{ "type": "CAWGIdentityAssertion", ... }` or
  `{ "type": "VerifiableCredential", ... }`.
- Organisational trust lists (IPTC Verified News Publisher) apply to the
  party's own credential, not to the DID document.

## 3. ISCC (ISO 24138)

```json
"alsoKnownAs": ["ISCC:KACYPXW445FTYNJ3CYSXHAFJMA2HUWULUNRFE3BLHRSCXYH2M5AEGQY"],
"content": { "softBindings": [ { "alg": "io.iscc.v0", "value": "ISCC:KACYPXW445FTYNJ3…" } ] }
```

(The value above is illustrative.) ISCC answers "is this *similar* content?",
`did:content` answers "is this *exactly* the content, and who controls it?".
Registries index soft bindings for near-duplicate lookup; clients never treat
an ISCC match as proof.

## 4. RSL 1.0, Content Signals, TDMRep

A `license[]` entry of type `RSLLicense` is isomorphic to an RSL
`<license>`:

```xml
<rsl xmlns="https://rslstandard.org/rsl">
  <content url="https://cdn.example.com/sample.png">
    <license>
      <permits type="usage">search</permits>
      <permits type="user">commercial non-commercial</permits>
      <prohibits type="usage">ai-train ai-input</prohibits>
      <payment type="attribution"/>
      <legal type="terms">https://label.example.com/licenses/standard</legal>
    </license>
  </content>
</rsl>
```

- Serve it with `Link: <…/license.xml>; rel="license"; type="application/rsl+xml"`
  next to `Link: <did:content:zQm…>; rel="describedby"`.
- Content Signals (`robots.txt`): `search=yes, ai-input=no, ai-train=no` is
  derived from the union of `permits`/`prohibits` over `search`, `ai-input`,
  `ai-train`.
- TDMRep: `tdm-reservation: 1` when `ai-train` is prohibited or absent;
  `tdm-policy: <terms URL>` when a paid `training` licence exists.
- The `LicenseNegotiation` service points at the RSL licence server or
  pay-per-crawl endpoint where the paid licence can be obtained.

## 5. On-chain IP registries (Story and similar)

| Story | did:content |
|---|---|
| IP Asset `ipId` (ERC-6551 account address) | `alsoKnownAs: ["https://explorer.story.foundation/ipa/0x…"]` or a CAIP-19 asset URI |
| License terms (PIL) | `license[] = { "type": "PIL", "terms": "<license terms URL or id>" }` |
| Royalty policy | `royalty.recipients[]` with `did:pkh:eip155:…` payees |
| Derivative registration | `derivedFrom[]` |
| On-chain proof | `provenance[] = { "type": "OnChainRegistration", "url": "<tx or explorer URL>" }` |

The DID can be created first (off-chain, free) and registered on a chain
later; the chain record then becomes additional provenance rather than the
root of trust.

## 6. Verifiable Credentials 2.0

- `credentialSubject.id = "did:content:zQm…"` for any claim about the
  content (licence grants, awards, takedown notices, AI-generated disclosure).
- Keys listed under `assertionMethod` in the DID document can issue such
  credentials *on behalf of the content* (e.g. an automated licence receipt).
- `digestMultibase` is the same term VC 2.0 uses in `relatedResource`, so a
  credential can reference the content bytes with the identical value.

## 7. DID Resolution and the Universal Resolver

- Resolution results use `application/did-resolution` with
  `didDocument`, `didDocumentMetadata`, `didResolutionMetadata`.
- A driver implements `GET /1.0/identifiers/{did}` by fetching
  `{registry}/.well-known/did-content/{scid}/did.jsonl`, running
  `verify_log`, and honouring `versionId` / `versionTime`.
- Errors: `invalidDid` (syntax), `notFound` (no registry has the log),
  `invalidDidDocument` (verification failed), `methodNotSupported`
  (unknown `parameters.method`).

## 8. Other content identifiers

| Identifier | Where it goes |
|---|---|
| ISRC / ISWC / ISBN / ISAN / EIDR / DOI | `alsoKnownAs` as URNs (`urn:isrc:…`, `doi:…`). They identify works or recordings; `did:content` identifies one file. |
| IPFS CID | `content.locations` (`ipfs://…`). A CID is already a multihash; a CIDv1 raw-leaf of the same bytes carries the same digest as `digestMultibase`. |
| Legacy `did:content` v0.1 | `alsoKnownAs` |
