import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { compareRuns, expandArgs, normalizeOutput, npxArgs, oathArgs, stripAnsi } from "./exec-parity-lib.mjs";

test("normalizeOutput strips ANSI, folds CRLF, trims trailing whitespace, and masks the root", () => {
  const raw = "\u001b[32mhello\u001b[0m  \r\n/tmp/root/x  \r\n\n\n";
  assert.equal(normalizeOutput(raw, { root: "/tmp/root" }), "hello\n<root>/x");
  assert.equal(stripAnsi("\u001b[1mA\u001b[22m"), "A");
  assert.equal(normalizeOutput("v1.2.3", { replace: [["^v", "", ""]] }), "1.2.3");
});

test("argument lists put the yes flag before the command and expand placeholders", () => {
  const testCase = { args: ["cowsay@1.6.0", "hi"] };
  assert.deepEqual(npxArgs(testCase), ["--yes", "cowsay@1.6.0", "hi"]);
  assert.deepEqual(oathArgs(testCase), ["x", "--yes", "cowsay@1.6.0", "hi"]);
  const split = { npx: ["-p", "a", "cmd"], oath: ["--package", "a", "cmd"] };
  assert.deepEqual(npxArgs(split), ["--yes", "-p", "a", "cmd"]);
  assert.deepEqual(oathArgs(split), ["x", "--yes", "--package", "a", "cmd"]);
  const expanded = expandArgs(["${FIXTURE:project-bin}", "${CWD}"], { fixtures: name => `/fixtures/${name}`, cwd: "/work" });
  assert.deepEqual(expanded, ["/fixtures/project-bin", "/work"]);
  assert.throws(() => expandArgs(["${FIXTURE:missing}"], { fixtures: () => null, cwd: "/" }));
});

test("compareRuns honors the comparison mode", () => {
  const a = { status: 0, stdout: "same\n" };
  const b = { status: 0, stdout: "same" };
  assert.equal(compareRuns(a, b, {}, {}).equivalent, true);
  const c = { status: 1, stdout: "npm error 404" };
  const d = { status: 1, stdout: "" };
  assert.equal(compareRuns(c, d, {}, {}).equivalent, false);
  assert.equal(compareRuns(c, d, { compare: "status" }, {}).equivalent, true);
  assert.equal(compareRuns(c, { status: 0, stdout: "" }, { compare: "status" }, {}).equivalent, false);
});

test("compareRuns never counts a run that did not finish as parity", () => {
  const hung = { status: null, stdout: "", error: { code: "ETIMEDOUT", message: "spawnSync node ETIMEDOUT" } };
  const result = compareRuns(hung, { ...hung }, {}, {});
  assert.equal(result.completed, false);
  assert.equal(result.equivalent, false);
  assert.equal(compareRuns({ status: null, stdout: "" }, { status: null, stdout: "" }, { compare: "status" }, {}).equivalent, false);
  assert.equal(compareRuns({ status: 0, stdout: "x" }, hung, {}, {}).equivalent, false);
  const done = compareRuns({ status: 0, stdout: "x" }, { status: 0, stdout: "x" }, {}, {});
  assert.equal(done.completed, true);
  assert.equal(done.equivalent, true);
});

test("the fixture set has at least 25 required cases with unique ids", async () => {
  const contract = JSON.parse(await readFile(new URL("../tests/compat/exec-fixtures.json", import.meta.url), "utf8"));
  const ids = contract.cases.map(c => c.id);
  assert.equal(new Set(ids).size, ids.length);
  const required = contract.cases.filter(c => !c.optional);
  assert.ok(required.length >= 25, `expected at least 25 required cases, found ${required.length}`);
  for (const testCase of contract.cases) {
    assert.ok(testCase.args || (testCase.npx && testCase.oath), `${testCase.id} needs args or npx+oath`);
    if (testCase.fixture) assert.match(testCase.fixture, /^[a-z0-9-]+$/);
  }
});
