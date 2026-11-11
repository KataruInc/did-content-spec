# Design rationale for did:content v0.2

This note explains *why* v0.2 looks the way it does, which 2024–2026
developments drove each decision, and what was wrong with v0.1. The normative
text is in [`../README.md`](../README.md).

## 1. What was broken in v0.1

| Problem | Consequence |
|---|---|
| The identifier was a hash of the whole DID document (`Base58(RIPEMD160(sha3-256(doc)))`). | Every update produced a *different DID*, so "Update" and a stable identifier were mutually exclusive. The sample document's `id` did not even match the algorithm. |
| `id_gen.py` base58-encoded the **hex string** of the digest instead of the bytes. | Identifiers were 55 characters instead of ~28, and incompatible with any other base58/multihash tooling. |
| The document had **no binding to the content bytes** ("The DID Document does not have a concrete property for content"). | A "content DID" that cannot prove which bytes it identifies is only a pointer into a database. |
| Resolution depended on a central database mapping DID → storage location. | Availability and integrity rested on one operator, which is exactly what the Motivation section criticised about S3/YouTube. |
| `controller` referenced `#author` / `#rights-holder` fragments of the DID itself; `verificationMethod` ids were malformed `did:key` values; `updation` is not a DID Core relationship; `proof.type: "Secp256k1"` is not a registered proof type. | The document did not validate against DID Core, so generic DID tooling (Universal Resolver, VC libraries) could not consume it. |
| `royaltyRecipients` carried an e-mail address and a float ratio. | Contradicted the Privacy section ("must not have PII") and broke canonicalisation. |

## 2. What changed in the market, 2024–2026

- **Provenance became infrastructure.** C2PA reached spec 2.3 (Jan 2026).
  Cameras from Leica, Sony, Nikon, Canon and the Google Pixel 10 sign at
  capture; Cloudflare preserves Content Credentials at the CDN; Google Search,
  YouTube, LinkedIn and TikTok surface them. The CAI counts 6,000+ members.
  The EU AI Act Article 50 obligations are enforced from 2 August 2026 and
  explicitly list cryptographic provenance (C2PA) as an acceptable method.
  ➜ A content identifier that is not *verifiable from the bytes* is no longer
  credible. Hence `content.hardBindings`, and the SCID committing to them.
- **Identity moved out of C2PA core into CAWG.** C2PA 2.0 dropped creator
  identity; the CAWG identity assertion (hosted at DIF since March 2025)
  restored it using X.509 or W3C Verifiable Credentials, with a fixed
  `cawg.*` role vocabulary and IPTC's Verified News Publisher list as a trust
  list. ➜ `parties[].role` reuses those roles, parties are DIDs, and
  human-readable identity is delegated to credentials referenced from
  `provenance`.
- **ISCC became ISO 24138 (2024) and a registered C2PA soft binding
  (`io.iscc.v0`).** ➜ Soft bindings use the C2PA algorithm registry rather
  than a home-grown field; ISCC is the recommended similarity identifier.
- **AI-usage licensing got machine-readable vocabularies.** RSL 1.0
  (September 2025; Reddit, Yahoo, Medium) defined `ai-train` / `ai-input` /
  `search` usage tokens and payment types; Cloudflare Content Signals (3.8M+
  domains) and W3C TDMRep express opt-outs; Cloudflare pay-per-crawl and RSL
  licence servers monetise them. ➜ `license[]` adopts the RSL tokens so that
  one declaration can be re-emitted as RSL XML, robots.txt lines or TDMRep.
- **On-chain IP registries proved demand for programmable rights.** Story's
  IP Asset Registry recorded 200k+ registrations in the first months of its
  2025 portal, with PIL licence terms, royalty splits and derivative graphs.
  ➜ `royalty`, `derivedFrom`, `license.type: "PIL"` and `did:pkh` payees make
  `did:content` a chain-agnostic equivalent that can also *point at* a chain
  record via `alsoKnownAs`/`provenance`.
- **DID methods converged on verifiable history.** `did:webvh` 1.0 (DIF,
  August 2025) and Bluesky's `did:plc` both use a self-certifying identifier,
  a signed hash-chained log, key pre-rotation and (webvh) witnesses. W3C
  published DID 1.1 (CR March 2026), Controlled Identifiers 1.0, DID
  Resolution 0.3 and Data Integrity 1.0 (REC May 2025). ➜ v0.2 adopts the
  webvh log model and the W3C stack verbatim instead of custom formats.

## 3. Key decisions

### 3.1 Hash of the genesis entry, not hash of the bytes

Two options were considered for the SCID: (a) the content hash itself,
(b) a hash of the genesis log entry (which *contains* the content hash).

(a) is attractive (one hash, one DID) but makes the DID uncontrollable:
anyone who has the bytes could publish a competing genesis with their own
keys, and two legitimate rights holders of identical bytes (e.g. a public
domain scan) could not have separate DIDs. (b) binds bytes **and** initial
controller in one identifier; duplicates of the same bytes under different
controllers get different DIDs, and the reverse-lookup API (§7.4) still finds
all of them from the hash. (b) is also what `did:webvh` and `did:plc` do, so
tooling and audits transfer.

### 3.2 Hard bindings are append-only

If a controller could replace the hash, the DID would silently come to mean
different content, defeating provenance. Edits therefore produce a new DID
linked by `derivedFrom`. Appending a second algorithm (e.g. blake3 next to
sha2-256) is allowed because it narrows, never widens, the set of matching
bytes.

### 3.3 Registries are untrusted

v0.1's resolver was a trusted database. In v0.2 anyone may mirror a log
(HTTPS, IPFS, a C2PA manifest, a chain) and resolvers verify everything.
This is the only way to honour the original motivation ("if storage goes
down, access becomes difficult") without becoming the new single point of
failure. Witnesses and watchers, borrowed from webvh, cover the residual
fork/withholding risk for DIDs that need it.

### 3.4 No PII, payment pointers instead of e-mail

Payment destinations are URIs with a standard (`payto:` RFC 8905,
`did:pkh`, Open Payments) so that settlement can be automated by a licence
server or a smart contract, and so that the public, permanent log never has
to be scrubbed of personal data.

### 3.5 Basis points, no floats

JCS (RFC 8785) canonicalisation of floats is a common source of
interoperability bugs; integers avoid it, and 1/10000 resolution matches
industry royalty practice.

### 3.6 Plain JSON first, JSON-LD compatible

Producers can treat documents as JSON; the published context makes them
valid JSON-LD for Verifiable Credential tooling. `@protected` terms prevent
redefinition attacks.

## 4. Adoption path

1. **Kataru**: issue a v0.2 DID for every uploaded work; serve logs at
   `https://did.kataru.io/.well-known/did-content/`; add the `Link` header
   and embed the DID in C2PA manifests on export.
2. **Universal Resolver driver**: a ~100-line HTTP wrapper around
   `verify_log`; register it so any DID-aware wallet/verifier resolves
   `did:content`.
3. **CAWG / IPTC**: propose `did:content` as a recommended `credentialSubject`
   for identity-claims-aggregation credentials about assets.
4. **RSL Collective**: document the `license[]` ↔ RSL XML mapping and ship a
   converter so publishers get RSL files for free from their DID documents.
5. **DID Method Registry**: update the entry to v0.2 and link the test
   vectors and conformance checks.

## 5. Sources

- W3C DID 1.1 — https://www.w3.org/TR/did-1.1/
- W3C DID Resolution 0.3 — https://www.w3.org/TR/did-resolution/
- W3C Controlled Identifiers 1.0 — https://www.w3.org/TR/cid-1.0/
- W3C Data Integrity 1.0 / EdDSA cryptosuites — https://www.w3.org/TR/vc-data-integrity/ , https://www.w3.org/TR/vc-di-eddsa/
- did:webvh 1.0 — https://identity.foundation/didwebvh/v1.0/
- did:plc — https://web.plc.directory/spec/v0.1/did-plc
- C2PA / Content Credentials adoption — https://editorsweblog.org/2026/04/12/c2pa-adoption-tracker-platforms-content-credentials-2026 , https://www.lumethic.com/en/articles/cameras-with-c2pa-content-credentials
- C2PA soft-binding algorithm list — https://github.com/c2pa-org/softbinding-algorithm-list
- CAWG identity assertion 1.1 — https://cawg.io/identity/1.1/
- IPTC media provenance / CAWG — https://iptc.org/media-provenance/
- ISCC / ISO 24138 — https://iscc.io/news/iso-publishes-new-standard-enabling-content-transparency-iso-24138
- RSL 1.0 — https://rslstandard.org/rsl , https://www.theregister.com/2025/12/10/really_simple_licensing_spec_takes/
- Cloudflare Content Signals — https://www.cloudflare.com/press-releases/2025/cloudflare-gives-creators-new-tool-to-control-use-of-their-content
- W3C TDMRep — https://www.w3.org/community/tdmrep
- EU AI Act Article 50 — https://www.orrick.com/en/Insights/2026/08/EU-AI-Act-Transparency-Obligations-for-AI-Generated-Content-Article-50
- Story Protocol IP Asset Registry / PIL — https://docs.story.foundation/smart-contract-reference/registry/ipassetregistry , https://www.forbes.com/sites/digital-assets/2025/03/25/reprogramming-ip-story-builds-a-blockchain-for-the-ai-era/
