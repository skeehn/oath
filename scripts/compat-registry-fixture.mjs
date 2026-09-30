#!/usr/bin/env node
import { createServer } from "node:http";
import { appendFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

function option(name) {
  const index = process.argv.indexOf(name);
  if (index === -1 || !process.argv[index + 1]) throw new Error(`${name} is required`);
  return process.argv[index + 1];
}

const portFile = resolve(option("--port-file"));
const logFile = resolve(option("--log-file"));
const token = process.env.OATH_COMPAT_REGISTRY_TOKEN ?? "oath-compat-token";
const username = process.env.OATH_COMPAT_REGISTRY_USER ?? "oath-compat-user";
const registryState = {
  tags: { latest: "1.0.0" },
  profile: { name: username, email: "compat@example.test", email_verified: true, fullname: "Oath Compatibility", tfa: null },
  org: { [username]: "developer" },
  teams: ["fixture-org:developers"],
  teamUsers: [username],
  packument: {
    _id: "fixture-package",
    _rev: "1-fixture",
    name: "fixture-package",
    homepage: "https://example.test/fixture-package/docs",
    bugs: { url: "https://example.test/fixture-package/issues" },
    repository: { type: "git", url: "git+https://example.test/fixture-package.git" },
    maintainers: [{ name: username, email: "compat@example.test" }],
    users: { [username]: true },
    "dist-tags": { latest: "1.0.0" },
    versions: {
      "1.0.0": {
        name: "fixture-package",
        version: "1.0.0",
        homepage: "https://example.test/fixture-package/docs",
        bugs: { url: "https://example.test/fixture-package/issues" },
        repository: { type: "git", url: "git+https://example.test/fixture-package.git" },
        dist: { tarball: "https://registry.invalid/fixture-package-1.0.0.tgz" },
      },
      "2.0.0": {
        name: "fixture-package",
        version: "2.0.0",
        homepage: "https://example.test/fixture-package/docs",
        bugs: { url: "https://example.test/fixture-package/issues" },
        repository: { type: "git", url: "git+https://example.test/fixture-package.git" },
        dist: { tarball: "https://registry.invalid/fixture-package-2.0.0.tgz" },
      },
    },
  },
};

const server = createServer(async (request, response) => {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  const body = Buffer.concat(chunks).toString("utf8");
  const authorization = request.headers.authorization ?? null;
  await appendFile(logFile, `${JSON.stringify({
    method: request.method,
    url: request.url,
    authorization: authorization ? "present" : "absent",
    body_sha256: body.length
      ? (await import("node:crypto")).createHash("sha256").update(body).digest("hex")
      : null,
  })}\n`);

  response.setHeader("content-type", "application/json");
  if (request.method === "GET" && request.url === "/-/whoami") {
    if (authorization === `Bearer ${token}`) {
      response.writeHead(200);
      response.end(JSON.stringify({ username }));
    } else {
      response.writeHead(401);
      response.end(JSON.stringify({ error: "unauthorized" }));
    }
    return;
  }
  if (request.url === "/-/npm/v1/user") {
    if (authorization !== `Bearer ${token}`) {
      response.writeHead(401);
      response.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    if (request.method === "GET") {
      response.writeHead(200);
      response.end(JSON.stringify(registryState.profile));
      return;
    }
    if (request.method === "POST") {
      const update = JSON.parse(body);
      if (Array.isArray(update.tfa)) {
        registryState.profile.tfa = { mode: registryState.profile.tfa?.requested_mode ?? "auth-and-writes", pending: false };
        response.writeHead(200);
        response.end(JSON.stringify({ tfa: ["recovery-one", "recovery-two"] }));
        return;
      }
      if (update.tfa?.mode === "disable") {
        registryState.profile.tfa = null;
        response.writeHead(200);
        response.end(JSON.stringify({ tfa: false }));
        return;
      }
      if (update.tfa?.mode === "auth-only" || update.tfa?.mode === "auth-and-writes") {
        registryState.profile.tfa = { pending: true, requested_mode: update.tfa.mode };
        response.writeHead(200);
        response.end(JSON.stringify({ tfa: "otpauth://totp/OathCompatibility?secret=JBSWY3DPEHPK3PXP" }));
        return;
      }
      registryState.profile = { ...registryState.profile, ...update };
      response.writeHead(200);
      response.end(JSON.stringify(registryState.profile));
      return;
    }
  }
  if (request.url === "/-/org/fixture-org/user") {
    if (authorization !== `Bearer ${token}`) {
      response.writeHead(401);
      response.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    if (request.method === "GET") {
      response.writeHead(200);
      response.end(JSON.stringify(registryState.org));
      return;
    }
    const membership = JSON.parse(body || "{}");
    if (request.method === "PUT") registryState.org[membership.user] = membership.role;
    if (request.method === "DELETE") delete registryState.org[membership.user];
    response.writeHead(200);
    response.end(JSON.stringify({ org: { name: "fixture-org", size: Object.keys(registryState.org).length }, user: membership.user, role: membership.role }));
    return;
  }
  if (request.url === "/-/org/fixture-org/team") {
    if (authorization !== `Bearer ${token}`) {
      response.writeHead(401);
      response.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    if (request.method === "GET") {
      response.writeHead(200);
      response.end(JSON.stringify(registryState.teams));
      return;
    }
    if (request.method === "PUT") {
      const name = JSON.parse(body).name;
      if (!registryState.teams.includes(`fixture-org:${name}`)) registryState.teams.push(`fixture-org:${name}`);
      response.writeHead(201);
      response.end(JSON.stringify({ name }));
      return;
    }
  }
  if (request.url?.startsWith("/-/team/fixture-org/developers/user")) {
    if (authorization !== `Bearer ${token}`) {
      response.writeHead(401);
      response.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    if (request.method === "GET") {
      response.writeHead(200);
      response.end(JSON.stringify(registryState.teamUsers));
      return;
    }
    const member = JSON.parse(body || "{}").user;
    if (request.method === "PUT" && !registryState.teamUsers.includes(member)) registryState.teamUsers.push(member);
    if (request.method === "DELETE") registryState.teamUsers = registryState.teamUsers.filter(user => user !== member);
    response.writeHead(200);
    response.end(JSON.stringify({ ok: true }));
    return;
  }
  if (request.url === "/-/team/fixture-org/developers" && request.method === "DELETE") {
    if (authorization !== `Bearer ${token}`) {
      response.writeHead(401);
      response.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    registryState.teams = registryState.teams.filter(team => team !== "fixture-org:developers");
    response.writeHead(204);
    response.end();
    return;
  }
  if (request.method === "GET" && request.url?.startsWith("/-/user/org.couchdb.user:")) {
    if (authorization !== `Bearer ${token}`) {
      response.writeHead(401);
      response.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    response.writeHead(200);
    const name = decodeURIComponent(request.url.split(":").at(-1));
    response.end(JSON.stringify({ name, email: `${name}@example.test` }));
    return;
  }
  if (request.method === "GET" && request.url?.startsWith("/-/_view/starredByUser")) {
    if (authorization !== `Bearer ${token}`) {
      response.writeHead(401);
      response.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    const rows = registryState.packument.users?.[username]
      ? [{ id: "fixture-package", key: username, value: "fixture-package" }]
      : [];
    response.writeHead(200);
    response.end(JSON.stringify({ rows }));
    return;
  }
  if (request.method === "POST" && request.url === "/-/v1/login") {
    const host = request.headers.host;
    response.writeHead(200);
    response.end(JSON.stringify({
      loginUrl: `http://${host}/web-login`,
      doneUrl: `http://${host}/-/v1/login/done`,
    }));
    return;
  }
  if (request.method === "GET" && request.url === "/-/v1/login/done") {
    response.writeHead(200);
    response.end(JSON.stringify({ token }));
    return;
  }
  if (request.method === "POST" && request.url === "/-/npm/v1/security/advisories/bulk") {
    response.writeHead(200);
    response.end("{}");
    return;
  }
  if (decodedStagePath(request.url) === "/-/stage") {
    if (authorization !== `Bearer ${token}`) {
      response.writeHead(401);
      response.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    if (request.method === "GET") {
      response.writeHead(200);
      response.end(JSON.stringify({ items: [{ id: "stage-fixture", packageName: "fixture-package", version: "2.0.0", tag: "next", createdAt: "2026-01-01T00:00:00.000Z", actor: username, actorType: "user", access: "public", shasum: "fixture" }] }));
      return;
    }
  }
  if (decodedStagePath(request.url) === "/-/stage/package/fixture-package" && request.method === "POST") {
    if (authorization !== `Bearer ${token}`) {
      response.writeHead(401);
      response.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    response.writeHead(201);
    response.end(JSON.stringify({ id: "stage-created", packageName: "fixture-package", version: "2.0.0", tag: "next" }));
    return;
  }
  if (decodedStagePath(request.url) === "/-/stage/stage-fixture/tarball" && request.method === "GET") {
    if (authorization !== `Bearer ${token}`) {
      response.writeHead(401);
      response.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    response.setHeader("content-type", "application/octet-stream");
    response.writeHead(200);
    response.end(Buffer.from("fixture-stage-tarball"));
    return;
  }
  if (decodedStagePath(request.url) === "/-/stage/stage-fixture/approve" && request.method === "POST") {
    if (authorization !== `Bearer ${token}` || request.headers["npm-otp"] !== "123456") {
      response.writeHead(401);
      response.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    response.writeHead(201);
    response.end(JSON.stringify({ message: "Package version approved and published successfully." }));
    return;
  }
  if (decodedStagePath(request.url) === "/-/stage/stage-fixture" && request.method === "DELETE") {
    if (authorization !== `Bearer ${token}` || request.headers["npm-otp"] !== "123456") {
      response.writeHead(401);
      response.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    response.writeHead(204);
    response.end();
    return;
  }
  if (decodedStagePath(request.url) === "/-/stage/stage-fixture" && request.method === "GET") {
    if (authorization !== `Bearer ${token}`) {
      response.writeHead(401);
      response.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    response.writeHead(200);
    response.end(JSON.stringify({ id: "stage-fixture", packageName: "fixture-package", version: "2.0.0", tag: "next", actor: username }));
    return;
  }
  if (request.url === "/-/npm/v1/tokens") {
    if (authorization !== `Bearer ${token}`) {
      response.writeHead(401);
      response.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    if (request.method === "GET") {
      response.writeHead(200);
      response.end(JSON.stringify({ objects: [{ key: "fixture-key", token: "abcd...wxyz", readonly: false, created: "2026-01-01T00:00:00.000Z", updated: "2026-01-01T00:00:00.000Z", cidr_whitelist: null }], urls: {}, total: 1 }));
      return;
    }
    if (request.method === "POST") {
      response.writeHead(201);
      response.end(JSON.stringify({ key: "generated-key", token: "generated-secret-token", readonly: Boolean(JSON.parse(body).readonly), cidr_whitelist: JSON.parse(body).cidr_whitelist ?? [] }));
      return;
    }
  }
  if (request.method === "DELETE" && request.url?.startsWith("/-/npm/v1/tokens/")) {
    if (authorization !== `Bearer ${token}`) {
      response.writeHead(401);
      response.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    response.writeHead(200);
    response.end(JSON.stringify({ ok: true }));
    return;
  }
  if (request.method === "GET" && request.url?.startsWith("/-/ping")) {
    response.writeHead(200);
    response.end(JSON.stringify({}));
    return;
  }
  if (request.method === "GET" && request.url?.startsWith("/-/v1/search")) {
    response.writeHead(200);
    response.end(JSON.stringify({
      objects: [
        { package: { name: "fixture-one", version: "1.0.0", description: "first fixture", keywords: [], date: "2026-01-01T00:00:00.000Z", links: {}, publisher: { username: "fixture" }, maintainers: [{ username: "fixture" }] }, score: { final: 1, detail: { quality: 1, popularity: 1, maintenance: 1 } }, searchScore: 1 },
        { package: { name: "fixture-two", version: "2.0.0", description: "second fixture", keywords: [], date: "2026-01-01T00:00:00.000Z", links: {}, publisher: { username: "fixture" }, maintainers: [{ username: "fixture" }] }, score: { final: 0.5, detail: { quality: 0.5, popularity: 0.5, maintenance: 0.5 } }, searchScore: 0.5 },
      ],
      total: 2,
      time: "1",
    }));
    return;
  }
  const decodedUrl = decodeURIComponent(request.url ?? "");
  const decodedPath = decodedUrl.split("?", 1)[0];
  const distTagsMatch = decodedUrl.match(/^\/-\/package\/(.+)\/dist-tags(?:\/([^/?]+))?/);
  if (distTagsMatch) {
    if (request.method !== "GET" && authorization !== `Bearer ${token}`) {
      response.writeHead(401);
      response.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    const tag = distTagsMatch[2];
    if (request.method === "GET" && !tag) {
      response.writeHead(200);
      response.end(JSON.stringify(registryState.tags));
      return;
    }
    if (request.method === "PUT" && tag) {
      registryState.tags[tag] = JSON.parse(body);
      registryState.packument["dist-tags"] = { ...registryState.tags };
      response.writeHead(201);
      response.end(JSON.stringify({ ok: true }));
      return;
    }
    if (request.method === "DELETE" && tag) {
      delete registryState.tags[tag];
      registryState.packument["dist-tags"] = { ...registryState.tags };
      response.writeHead(200);
      response.end(JSON.stringify({ ok: true }));
      return;
    }
  }
  if (decodedPath === "/fixture-package") {
    if (request.method === "GET") {
      response.writeHead(200);
      response.end(JSON.stringify(registryState.packument));
      return;
    }
    if (request.method === "PUT") {
      if (authorization !== `Bearer ${token}`) {
        response.writeHead(401);
        response.end(JSON.stringify({ error: "unauthorized" }));
        return;
      }
      registryState.packument = JSON.parse(body);
      response.writeHead(201);
      response.end(JSON.stringify({ ok: true, rev: "2-fixture" }));
      return;
    }
  }
  if (request.method === "PUT" && decodedPath.startsWith("/fixture-package/-rev/")) {
    if (authorization !== `Bearer ${token}`) {
      response.writeHead(401);
      response.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    const update = JSON.parse(body);
    registryState.packument.maintainers = update.maintainers;
    registryState.packument._rev = "2-fixture";
    response.writeHead(201);
    response.end(JSON.stringify({ ok: true, rev: "2-fixture" }));
    return;
  }
  if (request.method === "DELETE" && decodedPath.startsWith("/fixture-package/")) {
    if (authorization !== `Bearer ${token}`) {
      response.writeHead(401);
      response.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    response.writeHead(200);
    response.end(JSON.stringify({ ok: true }));
    return;
  }
  if (decodedPath === "/-/package/fixture-package/collaborators") {
    if (authorization !== `Bearer ${token}`) {
      response.writeHead(401);
      response.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    response.writeHead(200);
    response.end(JSON.stringify({ [username]: "read-write" }));
    return;
  }
  if (decodedPath === "/-/package/fixture-package/access" && request.method === "POST") {
    if (authorization !== `Bearer ${token}`) {
      response.writeHead(401);
      response.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    response.writeHead(200);
    response.end(JSON.stringify({ ok: true, access: JSON.parse(body).access }));
    return;
  }
  if (decodedPath === "/-/package/fixture-package/trust") {
    if (authorization !== `Bearer ${token}`) {
      response.writeHead(401);
      response.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    if (request.method === "GET") {
      response.writeHead(200);
      response.end(JSON.stringify([{ id: "trust-fixture", type: "github", claims: { repository: "owner/repository", workflow_ref: { file: "publish.yml" } } }]));
      return;
    }
    if (request.method === "POST") {
      response.writeHead(201);
      response.end(JSON.stringify([{ id: "trust-created", ...JSON.parse(body)[0] }]));
      return;
    }
  }
  if (request.method === "DELETE" && decodedPath.startsWith("/-/package/fixture-package/trust/")) {
    if (authorization !== `Bearer ${token}`) {
      response.writeHead(401);
      response.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    response.writeHead(200);
    response.end(JSON.stringify({ ok: true }));
    return;
  }
  if (decodedPath.startsWith("/-/team/") && decodedPath.endsWith("/package")) {
    if (authorization !== `Bearer ${token}`) {
      response.writeHead(401);
      response.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    response.writeHead(200);
    response.end(request.method === "GET" ? JSON.stringify({ "fixture-package": "read-write" }) : JSON.stringify({ ok: true }));
    return;
  }
  if (request.method === "DELETE" && request.url?.startsWith("/-/user/token/")) {
    response.writeHead(200);
    response.end(JSON.stringify({ ok: true }));
    return;
  }
  if ((request.method === "PUT" || request.method === "POST") && request.url?.includes("org.couchdb.user")) {
    response.writeHead(201);
    response.end(JSON.stringify({ ok: true, token }));
    return;
  }
  response.writeHead(404);
  response.end(JSON.stringify({ error: "not_found" }));
});

function decodedStagePath(url) {
  return decodeURIComponent(url ?? "").split("?", 1)[0];
}

server.listen(0, "127.0.0.1", async () => {
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("fixture server did not expose a TCP port");
  await writeFile(logFile, "");
  await writeFile(portFile, `${address.port}\n`);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
