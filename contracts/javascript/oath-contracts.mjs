import { createHash, createPublicKey, verify } from "node:crypto";

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function canonicalJson(value) {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new TypeError("oath-json-v1 accepts only safe JSON integers");
    }
    return String(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (typeof value === "object") {
    const members = Object.keys(value)
      .sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)))
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`);
    return `{${members.join(",")}}`;
  }
  throw new TypeError(`unsupported oath-json-v1 value: ${typeof value}`);
}

function decodeBase64(value, expectedBytes) {
  if (typeof value !== "string") return null;
  const decoded = Buffer.from(value, "base64");
  if (decoded.length !== expectedBytes || decoded.toString("base64") !== value) return null;
  return decoded;
}

export function verifySignedDocument(document) {
  const detached = document?.signature;
  if (detached?.algorithm !== "ed25519") return false;

  const publicKey = decodeBase64(detached.public_key, 32);
  const signature = decodeBase64(detached.signature, 64);
  if (publicKey === null || signature === null) return false;

  const payload = { ...document, signature: null };
  let signed = Buffer.from(canonicalJson(payload));
  if (detached?.canonicalization === "oath-json-v1+oath-domain-sha256-v1") {
    if (typeof detached.domain !== "string" || detached.domain.length === 0) return false;
    const domain = Buffer.from(detached.domain);
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(domain.length));
    signed = createHash("sha256")
      .update(Buffer.from("oath-domain-signature-v1\0"))
      .update(length)
      .update(domain)
      .update(createHash("sha256").update(signed).digest())
      .digest();
  } else if (detached?.canonicalization !== "oath-json-v1" || detached.domain !== undefined) {
    return false;
  }
  const key = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, publicKey]),
    format: "der",
    type: "spki",
  });
  return verify(null, signed, key, signature);
}
