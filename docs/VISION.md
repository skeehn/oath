# oath: the npm + npx rethink (vision)

Captured from Kyle, 2026-06-24. oath isn't just a secure installer — it's a bet that
npm/npx can be meaningfully rebuilt now that the cost of building the whole stack
(registry, CDN, verification, CLIs) has collapsed. npm is incredible software we're
grateful for; these are solvable problems npm can't safely change today without
risking the ecosystem.

## npm: the problems
- **Security.** npm is a giant target. Every new exploit makes npm add friction, and
  every layer makes life harder for good-faith devs.
- **Publishing is too hard** — regularly the hardest part of shipping a product.
- **Releases are immortal.** Typo a version and it's out there forever (e.g. TanStack
  Query shipped a wrong "latest" and can't revoke it). npm is paranoid about old apps'
  deps vanishing, so nothing can be taken down.

## npm: what a better platform does
- **Threshold revocation.** If a release has <100 installs or has been up <5h, the
  author can revoke it.
- **Pay-to-audit every release.** Bring your own Anthropic key or a card; the platform
  diffs every release and gives an AI "vibe check" on whether it's safe / intended.
- **Real visibility & metadata** — on the site *and* in the CLI at install time:
  obfuscated vs readable, open-source or not, who published the last release,
  permissions, a risk score. The **is‑odd‑with‑a‑zero** problem: a malicious typosquat
  installs identically to the real package today — that's a fundamental design failure.
  Different packages carry different risk; that risk must be upfront at decision time.
- **Kill name-squatting.** Verified name-handover (people + agents that actually vet),
  hard-ban squatting. (TanStack's npm name is held by a squatter, not Tanner.)

## npx: the rethink (the most exciting entry point)
- **npx as a shared executable layer** — like the browser lets you visit different
  sites, npx lets you run different code to solve different problems. Go further.
- **The npx prompt is useless.** "install the following package, ok? y/N" with only a
  version number. It should show: package size, author, who last changed it, a safety
  score, and the permissions it needs at runtime — for humans *and* agents.
- **Agent safety.** A `skill.md` that runs an `npx` command is a live supply-chain hole:
  if the package is taken over, the agent runs malicious code unknowingly. npx should
  surface enough info for the agent/user to decide or get a heads-up.
- **Pay-per-audit for small scripts** (~50¢): a verified third party reads your script
  and attaches a security score shown when anyone runs it. Must be third-party —
  self-run results can be faked.
- **Private registries.** A command to pull your own private packages (your bucket);
  publish to a private registry that's the default over the public one. "You and I could
  each have our own TanStack."

## The meta-point
npm's architecture assumes every package was expensive to make and has a maintainer
willing to fight npm. That's wrong — sharable software should be cheap. Doing this right
needs the whole stack (publishing integrations, registry, CDN, verification platform,
CLIs) — expensive before, tractable now. Socket already AI-audits releases and catches
exploits before npm does; there's enormous room to build better on top of / instead of npm.

## Where Oath stands today (v0.2.5 developer preview)

The install/exec side is implemented for the documented npm 11 workflow slices:
integrity-verified fetches, transactional linking, block-by-default dependency
scripts, AST and capability assessment, hash-bound approvals, agent-readable
verdicts, and explicit Linux/Windows containment reporting.

The platform is no longer entirely greenfield. `master` includes publish
assessments and signed handoffs plus a PostgreSQL registry control plane with
staging, private-package roles, short-lived identity tokens, replicated object
storage, signed revocation tombstones, dist-tag rollback, metrics, billing-event
verification, and transparency checkpoints.

That does not make Oath GA. Exact-master run 29499711576 passed 100 reviewed
workflow IDs on Linux, macOS, and Windows, 250 pinned project trees, 10,000
generated stress comparisons balanced across five execution modes, and native
capability tests. Those are compatibility and containment-harness results, not
detection or production-service proof. The complete detection targets,
performance targets, platform code signing, public registry/CDN operations,
anti-squatting governance, external security review, reliability SLOs, and
commercial adoption gates in [RELEASE_COMPLETE_PLAN.md](RELEASE_COMPLETE_PLAN.md)
remain open. `v0.2.5` must be described as a developer preview or private beta,
not a production-wide npm replacement.
