# Oath contract signatures

Oath decision contracts use Ed25519 over `oath-json-v1` bytes. The detached
signature object carries the base64 public key, base64 signature, algorithm,
and canonicalization version needed to reject unknown encodings. Registry
signatures may use `oath-json-v1+oath-domain-sha256-v1` plus a non-empty
`domain`; verifiers hash the version tag, length-prefixed domain, and SHA-256
payload digest before Ed25519 verification.

To verify an `ExecAssessment v3`, `PublishAssessment v2`, or
`RegistryVerdict v1`:

1. Validate the complete document against its published JSON Schema.
2. Retain the detached signature, then set the document's `signature` property
   to JSON `null`.
3. Encode the document as compact UTF-8 JSON. At every object depth, order keys
   lexicographically by Unicode scalar value. Preserve array order. Use normal
   JSON string escaping and base-10 JSON integer encoding; these contracts do
   not contain floating-point numbers.
4. Base64-decode `public_key` to exactly 32 bytes and `signature` to exactly 64
   bytes, then verify Ed25519 over the canonical bytes.

Signed tombstone and checkpoint bundles apply the same encoding directly to
their `payload` object. Evidence and policy digests are lowercase SHA-256 over
the same canonical bytes and include the `sha256:` prefix.

Unknown schema versions, signature algorithms, or canonicalization versions
must fail closed. A valid signature proves integrity under the included key; it
proves signer identity only when that public key is anchored through a trusted
release, registry, organization, or policy channel.

## Published bundle

Every release publishes an `oath-agent-contracts-<tag>.tar.gz` bundle containing
the three JSON Schemas, signed examples, TypeScript types, OpenAPI document,
JavaScript/Python/Go signature-verification clients, file manifest, and SHA-256
checksums. GitHub artifact attestations bind the bundle, manifest, and
individual schemas to the exact release workflow and source commit. Consumers
should verify both the release checksum and the attestation before trusting a
newly downloaded schema.

The reference clients verify the same three fixtures and reject a one-byte
semantic mutation. They intentionally do not select a trusted public key or
replace JSON Schema validation; callers must anchor accepted signer keys and
validate the complete document before acting on its decision. The HTTP and JSON
contracts are framework-neutral, so clients in other languages can implement
the same closed verification procedure without an Oath runtime dependency.

The reason-code set is closed within each schema version. Unknown reason codes
must be rejected instead of interpreted heuristically. Adding a reason code to
an existing schema requires synchronized Rust, TypeScript, schema, example, and
bundle-manifest changes; changing or removing a code requires a new schema
version.

## GA evidence contracts

The bundle also publishes closed JSON Schemas for `CompatibilityEvidence v1`,
`DetectionEvidenceReport v2`, `PerformanceEvidence v1` and v2,
`OperationalDrillReport v2`, `ProductionDeploymentEvidence v1`,
`TransparencyCheckpoint v3`, and `IndependentAuditReport v1`. These reports do
not authorize package execution and are not signed agent verdicts. They are
exact-commit inputs to the GA manifest, distributed with checksums and GitHub
artifact provenance. Missing, stale, self-test, expired, incomplete, or
threshold-failing reports remain open gates.

PerformanceEvidence v1 remains immutable for existing consumers. Version 2 adds
the verified warm no-op benchmark and per-install phase timings. The published
npm compatibility manifest is the authoritative list of GA-required commands,
semantics, implemented surfaces, preview surfaces, and intentional divergences.
`RegistryReplicationEvent v1` defines the provider-neutral immutable
event/object/checkpoint handoff for a future regional replicator; its presence
does not claim that multi-region replication has been deployed or qualified.

Two witness signatures are required for a qualifying transparency checkpoint;
the registry's own checkpoint signature is not an independent witness. Audit
reports bind the auditor's retained report and scope by digest without forcing
private findings into the public bundle.

Regenerate the deterministic examples and build the publication bundle with:

```sh
cargo run --locked -p oath-contracts --example generate_contract_examples -- contracts/examples
node scripts/build-contract-bundle.mjs contract-dist
(cd contract-dist && sha256sum --check SHA256SUMS)
```
