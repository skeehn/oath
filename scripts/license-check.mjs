import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import process from "node:process";

const root = resolve(import.meta.dirname, "..");

async function read(relativePath) {
  return readFile(resolve(root, relativePath), "utf8");
}

function requireMatch(contents, pattern, label) {
  if (!pattern.test(contents)) {
    throw new Error(`${label} does not declare Apache-2.0`);
  }
}

const [cargoToml, packageJson, packageLock, readme, notice, license, formula, cliMain] = await Promise.all([
  read("Cargo.toml"),
  read("website/package.json"),
  read("website/package-lock.json"),
  read("README.md"),
  read("NOTICE"),
  read("LICENSE"),
  read("homebrew/oath.rb"),
  read("crates/oath-cli/src/main.rs"),
]);

requireMatch(cargoToml, /^license = "Apache-2\.0"$/m, "Cargo workspace metadata");
requireMatch(readme, /\[Apache License 2\.0\]\(LICENSE\)/, "README");
requireMatch(notice, /^Oath\nCopyright 2026 Generalized Labs\n/m, "NOTICE");
requireMatch(
  license,
  /^                                 Apache License\n                           Version 2\.0, January 2004$/m,
  "LICENSE",
);
requireMatch(formula, /^  license "Apache-2\.0"$/m, "Homebrew formula");
requireMatch(
  formula,
  /^  url "https:\/\/github\.com\/Generalized-Labs\/oath\/archive\/refs\/tags\/v0\.2\.5\.tar\.gz"$/m,
  "Homebrew formula release URL",
);
if (!cliMain.includes('"license": "UNLICENSED"')) {
  throw new Error("oath init must not assign a license on the user's behalf");
}

const website = JSON.parse(packageJson);
const lock = JSON.parse(packageLock);
if (website.license !== "Apache-2.0") {
  throw new Error("website package metadata does not declare Apache-2.0");
}
if (lock.packages?.[""]?.license !== "Apache-2.0") {
  throw new Error("website lockfile root metadata does not declare Apache-2.0");
}

console.log("Apache-2.0 license declarations are consistent");
