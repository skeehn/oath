#!/usr/bin/env node
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";

const input = resolve(process.argv[2] ?? "evidence-download");
const output = resolve(process.argv[3] ?? "ga-evidence-manifest.json");
const releaseCommit = process.env.GITHUB_SHA ?? "local";

async function filesUnder(root) {
  const result = [];
  async function walk(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await walk(path);
      else result.push(path);
    }
  }
  await walk(root);
  return result.sort();
}

const artifacts = [];
for (const path of await filesUnder(input)) {
  const bytes = await readFile(path);
  let parsed = null;
  if (path.endsWith(".json")) {
    try { parsed = JSON.parse(bytes); } catch { parsed = null; }
  }
  artifacts.push({
    path: relative(input, path).replaceAll("\\", "/"),
    bytes: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    evidence_class: parsed?.evidence_class ?? null,
    summary: parsed && typeof parsed === "object" ? parsed : null,
  });
}

const behavioral = artifacts.filter((item) => item.path.endsWith("behavioral-summary.json"));
const project = artifacts.find((item) => item.path.endsWith("project-summary.json"));
const generated = artifacts.filter((item) =>
  item.summary?.evidence_class === "generated_stress" &&
  Array.isArray(item.summary?.results)
);
const summaries = artifacts.map((item) => item.summary).filter(Boolean);
const exactCommit = (report) => releaseCommit !== "local" && report?.release_commit === releaseCommit;
const fresh = (report, maximumDays = 30) => {
  const generated = Date.parse(report?.generated_at);
  return Number.isFinite(generated) && generated <= Date.now() + 5 * 60 * 1000 && generated >= Date.now() - maximumDays * 86400 * 1000;
};
const sha256Digest = (value) => /^sha256:[0-9a-f]{64}$/.test(value ?? "");
const completeMeasurement = (measurement) =>
  Number(measurement?.discovered) > 0 &&
  Number(measurement?.scanned) === Number(measurement?.discovered) &&
  Array.isArray(measurement?.scan_errors) && measurement.scan_errors.length === 0 &&
  sha256Digest(measurement?.dataset_digest);

const detection = summaries.find((item) =>
  item?.evidence_class === "detection-quality" && item?.schema_version === 2
);
const detectionCorpora = detection?.corpora ?? {};
const detectionPassed = exactCommit(detection) &&
  fresh(detection) &&
  detection?.qualification === "qualifying" &&
  detection?.qualifies_for_ga === true &&
  Array.isArray(detection?.errors) && detection.errors.length === 0 &&
  completeMeasurement(detectionCorpora.known_malware) &&
  completeMeasurement(detectionCorpora.benign) &&
  completeMeasurement(detectionCorpora.private_holdout) &&
  completeMeasurement(detectionCorpora.secret_exfiltration) &&
  Number(detectionCorpora.known_malware.rate) >= 0.99 &&
  Number(detectionCorpora.private_holdout.rate) >= 0.95 &&
  Number(detectionCorpora.benign.rate) <= 0.005 &&
  Number(detectionCorpora.secret_exfiltration.rate) === 1 &&
  detectionCorpora.private_holdout.family_separated === true &&
  detectionCorpora.private_holdout.time_separated === true &&
  detectionCorpora.private_holdout.labels_independently_held === true;

const betaValidation = summaries.find((item) =>
  item?.evidence_class === "beta-ledger-validation" && item?.schema_version === 1
);
const betaPassed = exactCommit(betaValidation) &&
  betaValidation?.qualifies_for_ga === true &&
  Number(betaValidation?.observed_days) >= 60 &&
  Array.isArray(betaValidation?.errors) && betaValidation.errors.length === 0;

const deployment = summaries.find((item) =>
  item?.evidence_class === "production-deployment" && item?.schema_version === 1
);
const deploymentPassed = exactCommit(deployment) &&
  deployment?.qualifies_for_ga === true &&
  Array.isArray(deployment?.regions) && new Set(deployment.regions).size >= 2 &&
  deployment?.offerings?.multi_tenant === true &&
  deployment?.offerings?.managed_isolated === true &&
  deployment?.offerings?.same_binaries_and_apis === true &&
  Object.values(deployment?.controls ?? {}).length >= 8 &&
  Object.values(deployment.controls).every((value) => value === true);

const performanceReports = summaries.filter((item) =>
  item?.evidence_type === "PerformanceEvidence" && [1, 2].includes(item?.schema_version)
);
const qualifyingPerformance = performanceReports.filter((item) =>
  releaseCommit !== "local" && item?.environment?.git_commit === releaseCommit &&
  fresh(item) &&
  item?.integrity?.tree_equivalent === true && item?.gates?.overall?.status === "pass" &&
  ["cold_install", "warm_install", "warm_noop", "cached_assessment", "cached_exec", "phase_regression"].every(
    (name) => item?.gates?.[name]?.status === "pass",
  ) &&
  item?.schema_version === 2 &&
  Number(item?.configuration?.minimum_qualifying_samples?.cold_install) >= 200 &&
  Number(item?.configuration?.minimum_qualifying_samples?.warm_install) >= 200 &&
  Number(item?.configuration?.minimum_qualifying_samples?.cached_assessment) >= 1000 &&
  Number(item?.configuration?.minimum_qualifying_samples?.cached_exec) >= 200
);
const performancePlatforms = new Set(qualifyingPerformance.map((item) => item.environment.platform));
const performancePassed = ["linux", "darwin", "win32"].every((platform) =>
  performancePlatforms.has(platform)
);

const compatibility = summaries.find((item) =>
  item?.evidence_type === "CompatibilityEvidence" && item?.schema_version === 1
);
const compatibilityPlatforms = new Set(
  Array.isArray(compatibility?.platforms) ? compatibility.platforms : [],
);
const compatibilityPassed = exactCommit(compatibility) && fresh(compatibility) &&
  compatibility?.qualifies_for_cli_ga === true &&
  Number(compatibility?.summary?.executed) > 0 &&
  Number(compatibility?.summary?.failed) === 0 &&
  Number(compatibility?.summary?.equivalent) === Number(compatibility?.summary?.executed) &&
  ["linux", "darwin", "win32"].every((platform) => compatibilityPlatforms.has(platform)) &&
  Array.isArray(compatibility?.node_versions) && compatibility.node_versions.length >= 2;

const checkpoint = summaries.find((item) =>
  item?.evidence_class === "transparency-checkpoint" && item?.schema_version === 3
);
const distinctWitnesses = new Set(
  Array.isArray(checkpoint?.witnesses) ? checkpoint.witnesses.map((item) => item?.identity) : [],
);
const checkpointPassed = exactCommit(checkpoint) &&
  Number(checkpoint.tree_size) > 0 &&
  sha256Digest(checkpoint.root_hash) &&
  sha256Digest(checkpoint.rekor_bundle_digest) &&
  distinctWitnesses.size >= 2 &&
  Date.parse(checkpoint.expires_at) > Date.now();

const audits = summaries.filter((item) => item?.evidence_class === "independent-security-audit");
const requiredAudits = ["architecture_review", "penetration_test", "sandbox_escape_review"];
const auditsPassed = requiredAudits.every((auditType) => audits.some((item) =>
  exactCommit(item) && item.audit_type === auditType && item.status === "passed" &&
  Number(item.open_critical) === 0 && Number(item.open_high) === 0
));
const stress = generated.reduce((acc, item) => {
  acc.executed += item.summary.results.length;
  acc.equivalent += item.summary.results.filter((result) => result.equivalent === true).length;
  acc.failed += item.summary.results.filter((result) => result.equivalent !== true).length;
  return acc;
}, { executed: 0, equivalent: 0, failed: 0 });

const independentBehavioral = {
  platform_reports: behavioral.length,
  executed: behavioral.reduce((sum, item) => sum + Number(item.summary?.executed ?? 0), 0),
  equivalent: behavioral.reduce((sum, item) => sum + Number(item.summary?.equivalent ?? 0), 0),
  failed: behavioral.reduce((sum, item) => sum + Number(item.summary?.failed ?? 0), 0),
};
const realProjects = {
  target: Number(project?.summary?.target ?? 0),
  exact_equivalents: Number(project?.summary?.exact_equivalents ?? 0),
  failures: project?.summary?.failures ?? [],
};
const sharedCliGates = [
  {
    name: "100 independent workflows across required platforms",
    passed: independentBehavioral.platform_reports >= 3 &&
      independentBehavioral.executed >= 300 &&
      independentBehavioral.equivalent === independentBehavioral.executed &&
      independentBehavioral.failed === 0,
  },
  {
    name: "250 pinned real projects",
    passed: realProjects.target >= 250 &&
      realProjects.exact_equivalents >= 250 &&
      realProjects.failures.length === 0,
  },
  {
    name: "10000 generated executions",
    passed: stress.executed >= 10000 &&
      stress.equivalent === stress.executed &&
      stress.failed === 0,
  },
  {
    name: "qualifying detection thresholds",
    passed: detectionPassed,
  },
  {
    name: "cross-platform npm/npx compatibility manifest",
    passed: compatibilityPassed,
  },
  {
    name: "cross-platform performance v2 thresholds",
    passed: performancePassed,
  },
];
const registryGates = [
  {
    name: "witnessed transparency checkpoint",
    passed: checkpointPassed,
  },
  {
    name: "independent architecture, penetration, and sandbox reviews",
    passed: auditsPassed,
  },
  {
    name: "60-day production SLO and disaster-drill ledger",
    passed: betaPassed,
  },
  {
    name: "multi-region production registry deployment",
    passed: deploymentPassed,
  },
  {
    name: "registry release candidate deployment identity",
    passed: sha256Digest(deployment?.deployment_digest),
  },
];

const evidenceGates = [...sharedCliGates, ...registryGates];

const technicalReady = evidenceGates.every((gate) => gate.passed);
const cliTechnicalReady = sharedCliGates.every((gate) => gate.passed);
const registryTechnicalReady = registryGates.every((gate) => gate.passed);

const manifest = {
  schema_version: 1,
  evidence_status: "developer-preview",
  commit: releaseCommit,
  run_id: process.env.GITHUB_RUN_ID ?? null,
  run_url: process.env.GITHUB_SERVER_URL && process.env.GITHUB_REPOSITORY && process.env.GITHUB_RUN_ID
    ? `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`
    : null,
  generated_at: new Date().toISOString(),
  claims: {
    independent_behavioral: independentBehavioral,
    generated_stress: stress,
    real_projects: realProjects,
    detection_quality: detection ?? null,
    compatibility: compatibility ?? null,
    transparency_checkpoint: checkpoint ?? null,
    independent_audits: audits,
    production_beta: betaValidation ?? null,
    production_deployment: deployment ?? null,
    performance: performanceReports,
  },
  ga_gate: {
    technical_ready: technicalReady,
    ready: false,
    completed_evidence_gates: evidenceGates.filter((gate) => gate.passed).map((gate) => gate.name),
    open_evidence_gates: evidenceGates.filter((gate) => !gate.passed).map((gate) => gate.name),
    open_external_gates: [
      "commercial adoption thresholds",
      "legal and compliance approval",
    ],
  },
  release_tracks: {
    cli: {
      status: "developer-preview",
      technical_ready: cliTechnicalReady,
      ready: false,
      completed_evidence_gates: sharedCliGates.filter((gate) => gate.passed).map((gate) => gate.name),
      open_evidence_gates: sharedCliGates.filter((gate) => !gate.passed).map((gate) => gate.name),
      open_external_gates: ["30-day public release-candidate qualification", "legal and release approval"],
    },
    registry: {
      status: "developer-preview",
      technical_ready: registryTechnicalReady,
      ready: false,
      completed_evidence_gates: registryGates.filter((gate) => gate.passed).map((gate) => gate.name),
      open_evidence_gates: registryGates.filter((gate) => !gate.passed).map((gate) => gate.name),
      open_external_gates: ["60-day production qualification", "external audit acceptance", "legal and release approval"],
    },
  },
  release_identity: {
    source_commit: releaseCommit,
    lockfile_sha256: process.env.OATH_LOCKFILE_SHA256 ?? null,
    toolchain: process.env.OATH_TOOLCHAIN ?? null,
    binary_digests: process.env.OATH_BINARY_DIGESTS ? JSON.parse(process.env.OATH_BINARY_DIGESTS) : {},
    deployment_id: deployment?.deployment_digest ?? null,
  },
  artifacts,
};

await mkdir(dirname(output), { recursive: true });
await writeFile(output, `${JSON.stringify(manifest, null, 2)}\n`);
console.log(JSON.stringify({ output, artifacts: artifacts.length, claims: manifest.claims }, null, 2));
