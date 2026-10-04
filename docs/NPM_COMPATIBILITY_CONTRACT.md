# npm compatibility contract

Oath targets workflow parity with npm 11 for install, ci, add/remove, run,
exec, workspaces, lockfile import, registry authentication, peer dependencies,
overrides, aliases, git/file/tarball dependencies, lifecycle behavior, and exit
status. Registry administration commands are outside this contract.

`scripts/npm-parity.mjs` is the executable differential specification. It runs
the same fixture in isolated temporary directories and emits a versioned JSON
artifact containing the pinned npm version, command results, normalized
`node_modules` trees, and equivalence decision. Differences are failures unless
documented as intentional security divergences with a stable Oath reason code.

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

The tree comparison includes `node_modules/.bin` entries on POSIX hosts: each
bin link must exist with the same name and the same relative target npm wrote.
Windows comparisons still exclude the shim directory because Oath does not yet
write npm's `cmd-shim` files there. The comparison also requires that neither
installer rewrote the fixture's `package.json` on a plain install or ci.

Known gaps still outside the executed contract (tracked in
`docs/FULL_REPLACEMENT_ROADMAP.md`): the parity harness runs `install` and `ci`
with `--ignore-scripts` only; `run`, `exec`, lifecycle scripts, `.npmrc`
beyond registry and token keys, `package-lock.json` output, and workspace
filter flags are not yet differentially tested. The optional
`OATH_COMPAT_INTEROP=1` probe records whether `npm install` after
`oath install` leaves the tree unchanged; it is reported, not required, until
Oath writes `package-lock.json` itself.

