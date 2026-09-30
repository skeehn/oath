# npm compatibility contract

Oath targets workflow parity with npm 11 across the command, subcommand, flag,
workspace, lockfile, registry authentication and administration, dependency,
lifecycle, output-state, and exit-status surfaces declared in
`contracts/npm-compatibility-manifest-v2.json`.

`scripts/npm-parity.mjs` covers deep install materialization. The independent
`scripts/compat-behavioral.mjs` suite covers install/ci workflow states, while
`scripts/compat-command-surface.mjs` executes all 69 declared commands, seven
npx/exec forms, and six workspace-filter forms for ci, add, remove, update,
exec, pack, and publish: 118 command-surface cases in total. Each runs npm and Oath in isolated twins and
records versions, arguments, command results, normalized state, authentication
requests, and equivalence. Differences fail unless documented as intentional
security or Oath-only product extensions with a stable manifest status.

The semantic tree comparison follows package links and excludes npm's
`.package-lock.json` plus Oath's `.oath` content-addressed implementation data.
Oath's internal `.oath-store-manifest.json` integrity record is also excluded.
Empty directories left by npm deduplication are normalized away because they
carry no package content. A dangling workspace link remains an explicit link
entry instead of crashing the comparator. Installed package names, links, and
package contents must otherwise be identical.

The required fixture corpus grows monotonically. Each fixed compatibility bug
must add a fixture before release.

The source matrix expands ten reviewed behavior fixtures across `npm install`
and `npm ci`, and clean, warm, offline, repeat, and interrupted states. This
creates 100 explicit named cases with stable IDs. CI executes every case on
Linux, macOS, and Windows. The matrix generator is deterministic and CI rejects
drift. These cases are not public release evidence until the exact-commit
cross-platform run passes, and maintainer review is not mislabeled as the
independent external review required for GA. Generated stress repetitions are
reported separately and default to 10,000 executions.

The real-project corpus is a frozen-input `npm install` materialization
contract. It verifies the exact lock digest before both runs. If npm rewrites
the output lock, only the paired `devOptional: true` to `dev: true` package
classification normalization may differ, and every changed JSON path is
retained in the evidence. All other lock changes fail. `npm ci` remains a
separate workflow contract and is not inferred from the real-project install
corpus.

The pinned project target is 250 projects, 25 in each category. Refreshes retain
the 100 previously verified exact commits and select 15 additional eligible
projects per category from a 498-repository reviewed pool. Every addition must
clone, produce a lock with Node 24.13.0 and npm 11.12.1, install successfully,
and pass compressed-lock checksum validation. Run `29366460579` produced the
reviewed 250-input manifest now checked into the repository. The 250-project
compatibility claim remains open until an exact-candidate parity run passes.

Known intentional fail-closed boundary: git dependencies must use an exact branch,
tag, or commit. npm-style `#semver:` git selectors are rejected with a stable
error instead of silently resolving a moving `HEAD`; exact tag-range resolution
remains outside the current supported slice.
