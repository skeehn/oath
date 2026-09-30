import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

const execFileAsync = promisify(execFile);
const aggregator = fileURLToPath(new URL("./aggregate-compatibility-evidence.mjs", import.meta.url));

test("aggregates every supported Node/platform report and fails closed on missing commands", async () => {
  const root = await mkdtemp(join(tmpdir(), "oath-compatibility-evidence-"));
  const input = join(root, "input");
  const output = join(root, "compatibility-evidence-v1.json");
  for (const platform of ["linux", "darwin", "win32"]) {
    for (const node of ["v22.22.3", "v24.13.0"]) {
      const path = join(input, platform, node, "behavioral-summary.json");
      await mkdir(dirname(path), { recursive: true });
      await writeFile(path, JSON.stringify({
        platform,
        node_version: node,
        reference_npm: "11.12.1",
        results: [{
          id: `${platform}-${node}`,
          command: "install",
          equivalent: true,
          npm: { status: 0, tree_sha256: "a".repeat(64) },
          oath: { status: 0, tree_sha256: "a".repeat(64) },
        }],
      }));
    }
  }
  await execFileAsync(process.execPath, [aggregator, input, output], {
    env: { ...process.env, OATH_RELEASE_COMMIT: "b".repeat(40) },
  });
  const evidence = JSON.parse(await readFile(output, "utf8"));
  assert.deepEqual(evidence.platforms, ["darwin", "linux", "win32"]);
  assert.equal(evidence.node_versions.length, 2);
  assert.equal(evidence.commands.length, 6);
  assert.equal(evidence.summary.failed, 0);
  assert.equal(evidence.qualifies_for_cli_ga, false);
});
