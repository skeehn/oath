export type OathDecision = "allow" | "deny" | "review" | "unknown";

export type OathReasonCode =
  | "OATH_EXEC_ALLOWED"
  | "OATH_EXEC_GRADE_BELOW_REQUIRED"
  | "OATH_EXEC_RELEASE_TOO_NEW"
  | "OATH_PUBLISH_ALLOWED"
  | "OATH_PUBLISH_SECRET_DETECTED"
  | "OATH_REGISTRY_ALLOWED"
  | "OATH_REGISTRY_CRITICAL_BEHAVIOR"
  | "OATH_REGISTRY_REVIEW_REQUIRED"
  | "OATH_REGISTRY_SECRET_DETECTED"
  | "OATH_REGISTRY_UNKNOWN";

export interface DetachedSignature {
  algorithm: "ed25519";
  canonicalization: "oath-json-v1" | "oath-json-v1+oath-domain-sha256-v1";
  domain?: string;
  public_key: string;
  signature: string;
}

export interface PackageIdentity {
  name: string;
  version: string;
  registry: string;
  integrity: string | null;
  publisher: string | null;
  publish_age_days: number | null;
  repository: string | null;
}

export interface ExecAssessmentV3 {
  schema_version: 3;
  generated_at: number;
  expires_at: number;
  identity: PackageIdentity;
  evidence: {
    unpacked_bytes: number;
    dependency_count: number;
    readable_source: boolean;
    obfuscated: boolean;
    native_code: boolean;
    lifecycle_hooks: boolean;
    capabilities: string[];
    findings: string[];
    limitations: string[];
    version_diff: Record<string, unknown> | null;
  };
  policy: { decision: OathDecision; reason_code: Extract<OathReasonCode, `OATH_EXEC_${string}`>; grade: string; score: number };
  sandbox: {
    backend: string;
    available: boolean;
    filesystem_isolation: boolean;
    network_isolation: boolean;
    process_isolation: boolean;
    resource_limits: boolean;
    degraded_reason: string | null;
  };
  policy_digest: string;
  evidence_digest: string;
  rule_bundle_version: string;
  signature: DetachedSignature;
}

export interface PublishAssessmentV2 {
  schema_version: 2;
  generated_at: number;
  expires_at: number;
  name: string;
  version: string;
  tag: string;
  access: string | null;
  package_digest: string;
  unpacked_bytes: number;
  files: Array<{ path: string; bytes: number; sha256: string }>;
  dependency_count: number;
  lifecycle_hooks: string[];
  capabilities: string[];
  source_available: boolean;
  secret_findings: string[];
  decision: OathDecision;
  reason_code: Extract<OathReasonCode, `OATH_PUBLISH_${string}`>;
  previous_release: {
    previous_version: string;
    added_files: string[];
    removed_files: string[];
    changed_files: string[];
    capabilities_added: string[];
    capabilities_removed: string[];
  } | null;
  policy_digest: string;
  evidence_digest: string;
  rule_bundle_version: string;
  limitations: string[];
  signature: DetachedSignature;
}

export interface RegistryVerdictV1 {
  schema_version: 1;
  generated_at: number;
  expires_at: number;
  package: PackageIdentity;
  decision: OathDecision;
  reason_code: Extract<OathReasonCode, `OATH_REGISTRY_${string}`>;
  risk_score: number;
  package_digest: string;
  assessment_digest: string;
  policy_digest: string;
  rule_bundle_version: string;
  limitations: string[];
  signature: DetachedSignature;
}
