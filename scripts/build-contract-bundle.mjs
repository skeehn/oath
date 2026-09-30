#!/usr/bin/env node
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const output = resolve(process.argv[2] ?? "contract-dist");
const schemas = [
  ["exec-assessment-v3.schema.json", 3, [
    "OATH_EXEC_ALLOWED",
    "OATH_EXEC_GRADE_BELOW_REQUIRED",
    "OATH_EXEC_RELEASE_TOO_NEW",
  ]],
  ["publish-assessment-v2.schema.json", 2, [
    "OATH_PUBLISH_ALLOWED",
    "OATH_PUBLISH_SECRET_DETECTED",
  ]],
  ["registry-verdict-v1.schema.json", 1, [
    "OATH_REGISTRY_ALLOWED",
    "OATH_REGISTRY_CRITICAL_BEHAVIOR",
    "OATH_REGISTRY_REVIEW_REQUIRED",
    "OATH_REGISTRY_SECRET_DETECTED",
    "OATH_REGISTRY_UNKNOWN",
  ]],
];
const examples = [
  "exec-assessment-v3.signed.json",
  "publish-assessment-v2.signed.json",
  "registry-verdict-v1.signed.json",
];
const evidenceSchemas = [
  ["compatibility-evidence-v1.schema.json", 1],
  ["detection-evidence-v2.schema.json", 2],
  ["independent-audit-report-v1.schema.json", 1],
  ["operational-drill-report-v2.schema.json", 2],
  ["performance-evidence-v1.schema.json", 1],
  ["performance-evidence-v2.schema.json", 2],
  ["production-deployment-evidence-v1.schema.json", 1],
  ["qualification-ledger-v1.schema.json", 1],
  ["registry-replication-event-v1.schema.json", 1],
  ["transparency-checkpoint-v3.schema.json", 3],
];
const compatibilityManifests = [
  "npm-compatibility-manifest-v1.json",
  "npm-compatibility-manifest-v2.json",
];

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function reasonCodes(schema) {
  if (schema.properties.reason_code?.enum) return schema.properties.reason_code.enum;
  return schema.$defs?.policy?.properties?.reason_code?.enum ?? [];
}

async function copy(relative, destination) {
  const source = join(root, relative);
  const target = join(output, destination);
  const bytes = await readFile(source);
  await mkdir(resolve(target, ".."), { recursive: true });
  await copyFile(source, target);
  return {
    path: destination,
    bytes: bytes.length,
    sha256: sha256(bytes),
  };
}

const within = (parent, child) => {
  const path = relative(parent, child);
  return path !== "" && !path.startsWith("..") && !isAbsolute(path);
};
const allowedRoots = [root, resolve(tmpdir()), resolve("/tmp"), resolve("/private/tmp")];
if (!basename(output).includes("contract") || !allowedRoots.some((parent) => within(parent, output))) {
  throw new Error("contract bundle output must be a contract-named directory inside the repository or temporary directory");
}
await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
const files = [];
for (const [name, version, expectedCodes] of schemas) {
  const source = join(root, "contracts", name);
  const schema = JSON.parse(await readFile(source, "utf8"));
  if (schema.$schema !== "https://json-schema.org/draft/2020-12/schema") {
    throw new Error(`${name}: unsupported JSON Schema dialect`);
  }
  if (schema.properties?.schema_version?.const !== version) {
    throw new Error(`${name}: schema version mismatch`);
  }
  if (schema.additionalProperties !== false || !schema.required?.includes("signature")) {
    throw new Error(`${name}: signed closed-object contract required`);
  }
  if (JSON.stringify(reasonCodes(schema)) !== JSON.stringify(expectedCodes)) {
    throw new Error(`${name}: reason-code catalog drift`);
  }
  files.push(await copy(`contracts/${name}`, `schemas/${name}`));
}

for (const [name, version] of evidenceSchemas) {
  const schema = JSON.parse(await readFile(join(root, "contracts", name), "utf8"));
  if (schema.$schema !== "https://json-schema.org/draft/2020-12/schema" ||
      schema.properties?.schema_version?.const !== version || schema.additionalProperties !== false) {
    throw new Error(`${name}: invalid closed evidence contract`);
  }
  files.push(await copy(`contracts/${name}`, `schemas/${name}`));
}

for (const name of examples) {
  const example = JSON.parse(await readFile(join(root, "contracts", "examples", name), "utf8"));
  if (example.signature?.algorithm !== "ed25519" || example.signature?.canonicalization !== "oath-json-v1") {
    throw new Error(`${name}: missing supported detached signature`);
  }
  files.push(await copy(`contracts/examples/${name}`, `examples/${name}`));
}

for (const compatibilityManifest of compatibilityManifests) {
  const manifest = JSON.parse(await readFile(join(root, "contracts", compatibilityManifest), "utf8"));
  if (compatibilityManifest.endsWith("v2.json")) {
    if (manifest.schema_version !== 2 || !Array.isArray(manifest.commands) || !manifest.commands.length) {
      throw new Error(`${compatibilityManifest}: invalid command-surface manifest`);
    }
    const implementation = new Set(manifest.status_definitions?.implementation ?? []);
    const evidence = new Set(manifest.status_definitions?.evidence ?? []);
    const commandNames = manifest.commands.map(command => command.name);
    if (new Set(commandNames).size !== commandNames.length) {
      throw new Error(`${compatibilityManifest}: duplicate command names`);
    }
    for (const command of manifest.commands) {
      if (!implementation.has(command.implementation) || !evidence.has(command.evidence)) {
        throw new Error(`${compatibilityManifest}: invalid status for ${command.name}`);
      }
      const surfaceIds = (command.surfaces ?? []).map(surface => surface.id);
      if (!surfaceIds.length || new Set(surfaceIds).size !== surfaceIds.length) {
        throw new Error(`${compatibilityManifest}: invalid surfaces for ${command.name}`);
      }
      for (const surface of command.surfaces) {
        if (!implementation.has(surface.implementation) || !evidence.has(surface.evidence)) {
          throw new Error(`${compatibilityManifest}: invalid status for ${surface.id}`);
        }
      }
    }
  }
  files.push(await copy(`contracts/${compatibilityManifest}`, `manifests/${compatibilityManifest}`));
}

files.push(await copy("contracts/oath-contracts.ts", "types/oath-contracts.ts"));
for (const [source, destination] of [
  ["contracts/javascript/oath-contracts.mjs", "javascript/oath-contracts.mjs"],
  ["contracts/javascript/verify-examples.mjs", "javascript/verify-examples.mjs"],
  ["contracts/python/oath_contracts.py", "python/oath_contracts.py"],
  ["contracts/python/requirements.txt", "python/requirements.txt"],
  ["contracts/python/test_examples.py", "python/test_examples.py"],
  ["contracts/go/go.mod", "go/go.mod"],
  ["contracts/go/oathcontracts/oathcontracts.go", "go/oathcontracts/oathcontracts.go"],
  ["contracts/go/oathcontracts/oathcontracts_test.go", "go/oathcontracts/oathcontracts_test.go"],
]) {
  files.push(await copy(source, destination));
}
files.push(await copy("contracts/registry-openapi.yaml", "openapi/registry-openapi.yaml"));
files.push(await copy("contracts/README.md", "README.md"));
files.sort((left, right) => left.path.localeCompare(right.path));

const commit = process.env.OATH_CONTRACT_COMMIT
  ?? process.env.GITHUB_SHA
  ?? execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error(`invalid contract commit: ${commit}`);
const workingTreeStatus = execFileSync(
  "git",
  ["status", "--porcelain", "--", "contracts", "scripts/build-contract-bundle.mjs"],
  { cwd: root, encoding: "utf8" },
).trim();
const sourceTreeClean = workingTreeStatus.length === 0;
if (!sourceTreeClean && process.env.OATH_CONTRACT_ALLOW_DIRTY !== "1") {
  throw new Error("contract inputs differ from the recorded commit; commit them or set OATH_CONTRACT_ALLOW_DIRTY=1 for a non-release local bundle");
}

const manifest = {
  schema_version: 1,
  bundle: "oath-agent-contracts",
  source_commit: commit,
  source_tree_clean: sourceTreeClean,
  contract_versions: {
    ExecAssessment: 3,
    PublishAssessment: 2,
    RegistryVerdict: 1,
  },
  evidence_contract_versions: Object.fromEntries(
    evidenceSchemas.map(([name, version]) => [name.replace(".schema.json", ""), version]),
  ),
  signature: {
    document_algorithm: "ed25519",
    canonicalization: "oath-json-v1",
    distribution_provenance: "GitHub artifact attestation",
  },
  reason_codes: schemas.flatMap(([, , codes]) => codes),
  files,
};
const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
await writeFile(join(output, "contract-manifest.json"), manifestBytes);
const checksums = [
  ...files.map((file) => `${file.sha256}  ${file.path}`),
  `${sha256(manifestBytes)}  contract-manifest.json`,
].join("\n");
await writeFile(join(output, "SHA256SUMS"), `${checksums}\n`);
await writeFile(
  join(output, "contract-manifest.json.sha256"),
  `${sha256(manifestBytes)}  contract-manifest.json\n`,
);
console.log(JSON.stringify({ output, source_commit: commit, files: files.length }, null, 2));
