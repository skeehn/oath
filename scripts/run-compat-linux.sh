#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target_dir="${OATH_LINUX_TARGET_DIR:-/private/tmp/oath-linux-compat-target}"
evidence_dir="${OATH_LINUX_EVIDENCE_DIR:-/private/tmp/oath-linux-compat-evidence}"
npm_version="${OATH_REFERENCE_NPM_VERSION:-11.16.0}"

mkdir -p "${target_dir}" "${evidence_dir}"

docker run --rm \
  --mount "type=bind,source=${repo_root},target=/workspace,readonly" \
  --mount "type=bind,source=${target_dir},target=/target" \
  --workdir /workspace \
  rust:1.94-bookworm \
  bash -lc 'apt-get update && apt-get install -y --no-install-recommends libseccomp-dev && CARGO_TARGET_DIR=/target cargo build --locked --release --bin oath'

for node_major in 22 24; do
  node_output="${evidence_dir}/node${node_major}"
  mkdir -p "${node_output}"
  docker run --rm \
    --mount "type=bind,source=${repo_root},target=/workspace,readonly" \
    --mount "type=bind,source=${target_dir},target=/target,readonly" \
    --mount "type=bind,source=${node_output},target=/evidence" \
    --workdir /workspace \
    --env OATH_BIN=/target/release/oath \
    --env OATH_COMPAT_RESULTS=/evidence \
    "node:${node_major}-bookworm" \
    bash -lc "npm install --global npm@${npm_version} && node scripts/compat-command-surface.mjs --execute"
done

echo "Linux compatibility evidence: ${evidence_dir}"
