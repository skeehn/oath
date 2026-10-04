import { readdir, readlink, realpath, stat } from "node:fs/promises";
import { join } from "node:path";

const ignoredEntries = new Set([
  ".package-lock.json",
  "oath-lock.json",
  ".oath-store-manifest.json",
  ".oath"
]);

// npm's bin-links write POSIX symlinks that Oath must reproduce exactly. On
// Windows npm writes cmd-shim files instead, which Oath does not emit yet, so
// the shim directory stays outside the comparison there.
const compareBinDirs = process.platform !== "win32";

export async function installedTree(root) {
  async function walk(dir, prefix = "") {
    let items;
    try {
      items = await readdir(dir, { withFileTypes: true });
    } catch (error) {
      if (error?.code === "ENOENT") return [];
      throw error;
    }

    const entries = [];
    for (const item of items.sort((a, b) => a.name.localeCompare(b.name))) {
      if (ignoredEntries.has(item.name)) continue;
      if (item.name === ".bin" && !compareBinDirs) continue;
      const relative = join(prefix, item.name);
      let directory = item.isDirectory();
      let child = join(dir, item.name);
      if (item.isSymbolicLink() && prefix.endsWith(".bin")) {
        // A bin entry is compared by its link text: same name, same relative
        // target as npm wrote. The target's bytes are already compared as part
        // of the package it belongs to.
        entries.push(`b:${relative} -> ${(await readlink(child)).replaceAll("\\", "/")}`);
        continue;
      }
      if (item.isSymbolicLink()) {
        try {
          child = await realpath(child);
          directory = (await stat(child)).isDirectory();
        } catch (error) {
          if (error?.code !== "ENOENT") throw error;
          entries.push(`l:${relative}`);
          continue;
        }
      }

      if (!directory) {
        entries.push(`f:${relative}`);
        continue;
      }

      if (prefix.split(/[\\/]/).length >= 4) {
        entries.push(`d:${relative}`);
        continue;
      }

      const descendants = await walk(child, relative);
      // npm can leave empty scope directories after deduplication. They carry
      // no package contents and Oath intentionally does not materialize them.
      if (descendants.length > 0) entries.push(`d:${relative}`, ...descendants);
    }
    return entries;
  }

  return walk(root);
}
