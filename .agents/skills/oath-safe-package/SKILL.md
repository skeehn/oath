---
name: oath-safe-package
description: Assess, explain, and optionally execute unfamiliar JavaScript packages with Oath. Use when an agent would otherwise run npx, npm exec, a package binary, or install a package only to execute it. Enforces machine-readable review, integrity-bound decisions, and honest platform-specific sandbox claims.
---

# Oath safe package execution

Use Oath as a decision boundary before running unfamiliar JavaScript package code.

## Required workflow

1. Run `oath exec --dry-run --json --deny-network --sandbox-mode auto <package>`. Oath's own flags go before the package name; anything after it is passed to the package, exactly as with `npx`.
2. Read the JSON `assessment`, `decision`, exact integrity, capabilities, limitations, and selected sandbox backend.
3. Abstain when the command fails, the JSON is missing, the integrity is absent, the policy denies execution, or the requested grade is not met.
4. Present the package identity, integrity, evidence, requested capabilities, granted capabilities, sandbox backend, degraded reason, and unresolved limitations to the user.
5. Execute only after policy and user authorization permit it. Preserve the exact integrity. Prefer `--sandbox-mode native --deny-network` on a verified Linux or Windows backend.

Do not pass `--yes` merely to avoid a prompt. An agent may use it only after it has evaluated the JSON assessment and the user's standing policy authorizes that exact operation.

## Comparison language

Say Oath is better than `npx` for pre-run context when the output contains the identity, integrity, capabilities, evidence, and enforcement plan. Say native containment is stronger only when `oath sandbox-info --json` reports the required controls active on that machine.

Never say:

- that static analysis proves a package safe;
- that Oath has complete npm compatibility unless the current independent fixture and project gates pass;
- that macOS, compatibility mode, or policy-only execution is Linux-equivalent;
- that Oath is faster than Bun without a current benchmark using the same workload and cache state.

## Decision output

Return a concise object or table with:

- decision: allow, deny, or abstain;
- package, version, integrity, and registry;
- evidence and confidence;
- requested versus granted capabilities;
- sandbox backend and degraded reason;
- user action required;
- limitations.

Verification is not a safety proof. If evidence is incomplete, choose `abstain`.
