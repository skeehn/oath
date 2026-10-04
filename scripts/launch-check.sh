#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MIN_FREE_MIB="${MIN_FREE_MIB:-10240}"
case "$ROOT" in
  *"Mobile Documents"*|*"iCloud"*)
    echo "launch check must run from a hydrated non-iCloud clone; got $ROOT" >&2
    exit 1
    ;;
esac
FREE_MIB="$(df -Pm "$ROOT" | awk 'NR==2 {print $4}')"
if [[ -z "$FREE_MIB" || "$FREE_MIB" -lt "$MIN_FREE_MIB" ]]; then
  echo "launch check needs at least ${MIN_FREE_MIB} MiB free at $ROOT (found ${FREE_MIB:-unknown})" >&2
  exit 1
fi

SMOKE_HOME="$(mktemp -d "${TMPDIR:-/tmp}/oath-smoke-home.XXXXXX")"
SMOKE_PROJECT="$(mktemp -d "${TMPDIR:-/tmp}/oath-smoke-project.XXXXXX")"
SCOPED_PROJECT="$(mktemp -d "${TMPDIR:-/tmp}/oath-smoke-scoped.XXXXXX")"
ALIAS_PROJECT="$(mktemp -d "${TMPDIR:-/tmp}/oath-smoke-alias.XXXXXX")"
RUN_PROJECT="$(mktemp -d "${TMPDIR:-/tmp}/oath-smoke-run.XXXXXX")"
WORKSPACE_PROJECT="$(mktemp -d "${TMPDIR:-/tmp}/oath-smoke-workspace.XXXXXX")"
if [[ -n "${OATH_LAUNCH_TARGET_DIR:-}" ]]; then
  mkdir -p "$OATH_LAUNCH_TARGET_DIR"
  BUILD_TARGET="$(cd "$OATH_LAUNCH_TARGET_DIR" && pwd)"
  CLEAN_BUILD_TARGET=0
else
  BUILD_TARGET="$(mktemp -d "${TMPDIR:-/tmp}/oath-launch-target.XXXXXX")"
  CLEAN_BUILD_TARGET=1
fi

cleanup() {
  rm -rf "$SMOKE_HOME" "$SMOKE_PROJECT" "$SCOPED_PROJECT" "$ALIAS_PROJECT" "$RUN_PROJECT" "$WORKSPACE_PROJECT"
  if [[ "$CLEAN_BUILD_TARGET" == "1" ]]; then
    rm -rf "$BUILD_TARGET"
  fi
}
trap cleanup EXIT

cd "$ROOT"
export CARGO_TARGET_DIR="$BUILD_TARGET"

echo "using cargo target dir: $CARGO_TARGET_DIR"

echo "==> format"
cargo fmt --all -- --check

echo "==> license declarations"
node scripts/license-check.mjs

echo "==> clippy"
cargo clippy --workspace --locked --all-targets -- -D warnings

echo "==> tests"
cargo test --workspace --locked

if command -v cargo-audit >/dev/null 2>&1; then
  echo "==> cargo audit"
  cargo audit --deny warnings
else
  echo "==> cargo audit skipped: install with 'cargo install cargo-audit'"
fi

echo "==> release build"
cargo build --release --locked --bin oath

echo "==> release smoke install"
(
  cd "$SMOKE_PROJECT"
  BIN="$CARGO_TARGET_DIR/release/oath"
  HOME="$SMOKE_HOME" "$BIN" install --yes is-number
  node -e 'const isNumber = require("is-number"); if (!isNumber(42)) process.exit(1)'

  HOME="$SMOKE_HOME" "$BIN" add --yes is-odd
  node -e 'const isOdd = require("is-odd"); if (!isOdd(3)) process.exit(1)'

  HOME="$SMOKE_HOME" "$BIN" install --yes is-sorted
  node -e 'const isNumber = require("is-number"); const isOdd = require("is-odd"); const isSorted = require("is-sorted"); if (!isNumber(7) || !isOdd(3) || !isSorted([1,2,3])) process.exit(1)'

  if HOME="$SMOKE_HOME" "$BIN" install --frozen-lockfile isarray; then
    echo "expected frozen package install to fail" >&2
    exit 1
  fi

  mkdir -p node_modules/stale
  touch node_modules/stale/should-disappear
  HOME="$SMOKE_HOME" "$BIN" ci
  test ! -e node_modules/stale/should-disappear

  HOME="$SMOKE_HOME" "$BIN" remove is-odd
  node -e 'const isNumber = require("is-number"); if (!isNumber(7)) process.exit(1)'
  HOME="$SMOKE_HOME" "$BIN" verify

  # Tamper the store copy the project actually links. The store may also hold
  # an is-number version that a removed package once needed; that copy is no
  # longer in the lock, so verify is right not to flag it.
  IS_NUMBER_VERSION="$(node -p "require('./node_modules/is-number/package.json').version")"
  STORE_PACKAGE_JSON="$(find "$SMOKE_HOME/.oath/store" -path "*/is-number/$IS_NUMBER_VERSION/*package.json" -print -quit)"
  test -n "$STORE_PACKAGE_JSON"
  cp "$STORE_PACKAGE_JSON" "$STORE_PACKAGE_JSON.bak"
  printf '\n// tamper\n' >> "$STORE_PACKAGE_JSON"
  if HOME="$SMOKE_HOME" "$BIN" verify; then
    echo "expected verify to fail after store tamper" >&2
    exit 1
  fi
  mv "$STORE_PACKAGE_JSON.bak" "$STORE_PACKAGE_JSON"
  HOME="$SMOKE_HOME" "$BIN" verify
)

echo "==> release smoke scoped package"
(
  cd "$SCOPED_PROJECT"
  BIN="$CARGO_TARGET_DIR/release/oath"
  HOME="$SMOKE_HOME" "$BIN" add --yes @types/node
  test -e node_modules/@types/node/package.json
)

echo "==> release smoke npm alias"
(
  cd "$ALIAS_PROJECT"
  BIN="$CARGO_TARGET_DIR/release/oath"
  HOME="$SMOKE_HOME" "$BIN" install --yes alias-number@npm:is-number@latest
  node -e 'const isNumber = require("alias-number"); if (!isNumber(9)) process.exit(1)'
)

echo "==> release smoke exec json"
(
  cd "$SMOKE_PROJECT"
  BIN="$CARGO_TARGET_DIR/release/oath"
  HOME="$SMOKE_HOME" "$BIN" exec --dry-run --json is-number > exec.json
  node -e 'const r = require("./exec.json"); if (r.name !== "is-number" || r.decision === "deny" || r.sandbox_effective !== "off") process.exit(1)'

  HOME="$SMOKE_HOME" "$BIN" sandbox-info --json > sandbox-capabilities.json
  if node -e 'const c = require("./sandbox-capabilities.json"); process.exit(c.available && c.filesystem_isolation && c.network_isolation && c.process_isolation && c.resource_limits ? 0 : 1)'; then
    HOME="$SMOKE_HOME" "$BIN" exec --dry-run --json --sandbox is-number > exec-sandbox.json
    node -e 'const r = require("./exec-sandbox.json"); if (r.name !== "is-number" || r.sandbox_mode !== "auto" || r.sandbox_effective !== "native") process.exit(1)'
  else
    if HOME="$SMOKE_HOME" "$BIN" exec --dry-run --json --sandbox is-number; then
      echo "expected automatic sandbox mode to fail closed without complete native containment" >&2
      exit 1
    fi
    HOME="$SMOKE_HOME" "$BIN" exec --dry-run --json --sandbox --allow-degraded-sandbox is-number > exec-sandbox.json
    node -e 'const r = require("./exec-sandbox.json"); if (r.name !== "is-number" || r.sandbox_mode !== "auto" || r.sandbox_effective !== "node" || !r.sandbox_degraded_allowed) process.exit(1)'
  fi
)

echo "==> release smoke run args"
(
  cd "$RUN_PROJECT"
  BIN="$CARGO_TARGET_DIR/release/oath"
  printf '%s\n' '{"name":"run-smoke","version":"1.0.0","scripts":{"echoargs":"node print-args.js"}}' > package.json
  printf '%s\n' 'const fs = require("fs");' 'fs.writeFileSync("args.json", JSON.stringify(process.argv.slice(2)));' > print-args.js
  HOME="$SMOKE_HOME" "$BIN" run echoargs -- "hello world" "semi;colon" "quote'arg" ""
  node -e 'const a = require("./args.json"); if (a.length !== 4 || a[0] !== "hello world" || a[1] !== "semi;colon" || a[2] !== "quote'\''arg" || a[3] !== "") process.exit(1)'
)

echo "==> release smoke global bin"
(
  BIN="$CARGO_TARGET_DIR/release/oath"
  HOME="$SMOKE_HOME" "$BIN" install -g --yes mkdirp
  test -x "$SMOKE_HOME/.oath/global/bin/mkdirp"
)

echo "==> release smoke workspace"
(
  cd "$WORKSPACE_PROJECT"
  mkdir -p packages/a
  printf '%s\n' '{"private":true,"workspaces":["packages/*"]}' > package.json
  printf '%s\n' '{"name":"@smoke/a","version":"1.0.0","dependencies":{"is-number":"^7.0.0"}}' > packages/a/package.json
  BIN="$CARGO_TARGET_DIR/release/oath"
  HOME="$SMOKE_HOME" "$BIN" install --yes
  test -e node_modules/@smoke/a/package.json
)

echo "launch check passed"
