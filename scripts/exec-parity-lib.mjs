// Helpers for the exec parity harness (scripts/exec-parity.mjs): argument
// expansion, output normalization, and the comparison rule. Kept separate so
// `node --test scripts/exec-parity.test.mjs` can exercise them without
// running npx.

/** Strip ANSI escape sequences. */
export function stripAnsi(text) {
  // eslint-disable-next-line no-control-regex
  return text.replace(/\u001b\[[0-9;]*[A-Za-z]/g, "");
}

/**
 * Normalize program output for comparison: ANSI stripped, CRLF folded to LF,
 * trailing whitespace trimmed per line, trailing blank lines dropped, the
 * temporary root replaced by a placeholder, then any per-case replacements.
 */
export function normalizeOutput(text, { root = null, replace = [] } = {}) {
  let out = stripAnsi(text ?? "").replace(/\r\n/g, "\n");
  if (root) {
    out = out.split(root).join("<root>");
  }
  for (const [pattern, flags, replacement] of replace) {
    out = out.replace(new RegExp(pattern, flags), replacement);
  }
  return out
    .split("\n")
    .map(line => line.replace(/\s+$/, ""))
    .join("\n")
    .replace(/\n+$/, "");
}

/**
 * Expand `${FIXTURE:name}` placeholders to the absolute fixture path and
 * `${CWD}` to the working directory.
 */
export function expandArgs(args, { fixtures, cwd }) {
  return args.map(arg =>
    arg
      .replace(/\$\{FIXTURE:([^}]+)\}/g, (_, name) => {
        const path = fixtures(name);
        if (!path) throw new Error(`unknown exec fixture ${name}`);
        return path;
      })
      .replace(/\$\{CWD\}/g, cwd)
  );
}

/** The `npx` argument list for a case: npm flags must precede the command. */
export function npxArgs(testCase) {
  return ["--yes", ...(testCase.npx ?? testCase.args)];
}

/** The `oath x` argument list for a case. */
export function oathArgs(testCase) {
  return ["x", "--yes", ...(testCase.oath ?? testCase.args)];
}

/**
 * Compare two runs. `compare` is "stdout" (exit code and normalized stdout
 * must match) or "status" (only the exit code must match, for output that
 * is inherently different such as error text on stdout). A run that timed
 * out or failed to start has no exit code (`status: null`, or `error` set),
 * and two of those are not evidence of parity: the case is not equivalent.
 */
export function compareRuns(npx, oath, testCase, context) {
  const compare = testCase.compare ?? "stdout";
  const npxStdout = normalizeOutput(npx.stdout, context);
  const oathStdout = normalizeOutput(oath.stdout, context);
  const completed = [npx, oath].every(run => Number.isInteger(run.status) && !run.error);
  const statusEqual = completed && npx.status === oath.status;
  const stdoutEqual = compare === "status" || npxStdout === oathStdout;
  return {
    equivalent: statusEqual && stdoutEqual,
    completed,
    status_equal: statusEqual,
    stdout_equal: stdoutEqual,
    npx_stdout: npxStdout,
    oath_stdout: oathStdout
  };
}
