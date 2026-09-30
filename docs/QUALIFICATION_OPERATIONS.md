# Qualification operations

Oath maintains independent, signed qualification ledgers for the CLI and the
Registry. A ledger is evidence of an elapsed observation window, not a project
plan. Never add synthetic observations to a release ledger.

## Create a pending ledger

Generate the candidate binary or deployment manifest first and calculate its
SHA-256 digest. Initialize the appropriate track:

```sh
node scripts/qualification-ledger.mjs init \
  --track cli \
  --commit 0123456789abcdef0123456789abcdef01234567 \
  --artifact oath=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --output qualification/cli-ledger.json
```

Use `--track registry` for the 60-day Registry ledger. Initialization leaves
every prerequisite open and the window in `pending` state.

Record each prerequisite only after its referenced evidence has passed:

```sh
node scripts/qualification-ledger.mjs prerequisite qualification/cli-ledger.json \
  --id exact_commit_compatibility \
  --evidence evidence/compatibility.json=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

The CLI prerequisites are exact-commit compatibility, cross-platform
performance, containment audit, and RC deployment. Registry prerequisites are
external audits, operational drills, hosted failover, and RC deployment. The
window cannot start while any prerequisite is open.

## Start and observe

Start only after deploying the exact recorded artifact:

```sh
node scripts/qualification-ledger.mjs start qualification/cli-ledger.json
node scripts/qualification-ledger.mjs observe qualification/cli-ledger.json \
  --date 2030-01-01 \
  --evidence monitoring/2030-01-01.json=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Observations must be unique, consecutive UTC dates, healthy, free of unresolved
critical defects, bound to the same candidate, and supported by checksummed
evidence. The ledger reaches `completed` only after 30 CLI or 60 Registry days.

## Reset rules

CLI changes to resolution, lockfiles, lifecycle execution, containment, or
artifact verification reset its window. Registry changes to architecture,
security policy, signing, replication, or schema reset its window. A reset
clears observations and reopens every prerequisite:

```sh
node scripts/qualification-ledger.mjs reset qualification/cli-ledger.json \
  --rule containment \
  --reason "changed native sandbox policy" \
  --commit fedcba9876543210fedcba9876543210fedcba98 \
  --artifact oath=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
```

## Signing and monitoring

Keep the Ed25519 private key outside the repository. Every mutation invalidates
the signature, so sign after recording an observation or reset:

```sh
node scripts/qualification-ledger.mjs sign qualification/cli-ledger.json --key /secure/qualification-ed25519.pem
node scripts/qualification-ledger.mjs verify qualification/cli-ledger.json
node scripts/monitor-qualification.mjs qualification/cli-ledger.json --max-age-hours 36
```

The monitor exits nonzero for invalid signatures, open prerequisites, pending or
reset windows, stale running windows, candidate changes, gaps, unhealthy days,
or a completed ledger that does not qualify. The reusable
`qualification-monitor.yml` workflow provides the same check for CI or a daily
external scheduler. Do not schedule it until a real ledger is available.

The self-tests are synthetic and can only validate the tooling:

```sh
node scripts/qualification-ledger.mjs --self-test
node scripts/monitor-qualification.mjs --self-test
```
