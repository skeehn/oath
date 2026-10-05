//! Pattern definitions for static analysis
//!
//! Encodes knowledge of:
//! - How packages access system resources
//! - Known malicious obfuscation techniques (ua-parser-js, event-stream, node-ipc)
//! - Typosquatting targets
//! - 2024-2025 attack vectors: crypto mining, credential harvest, second-stage
//!   downloads, DNS exfil, conditional payloads, postinstall abuse
//!
//! Current pattern count: 29 (plus slopsquatting, which is a metadata check
//! handled separately in the name-similarity analyzer, not a string scan)

use crate::report::{FindingKind, RiskLevel};

/// A pattern rule: what to detect, what risk it implies
#[derive(Debug, Clone)]
pub struct Pattern {
    pub id: &'static str,
    pub kind: FindingKind,
    pub risk: RiskLevel,
    pub description: &'static str,
    /// String patterns to scan for (fast pre-filter before AST check)
    pub strings: &'static [&'static str],
}

/// All built-in detection patterns
pub static PATTERNS: &[Pattern] = &[
    // ---- NETWORK ----
    Pattern {
        id: "net-fetch",
        kind: FindingKind::Network,
        risk: RiskLevel::Info,
        description: "Uses fetch() API for network requests",
        strings: &["fetch(", "fetch ("],
    },
    Pattern {
        id: "net-http-require",
        kind: FindingKind::Network,
        risk: RiskLevel::Low,
        description: "Requires http/https/net module",
        strings: &[
            "require('http')",
            "require(\"http\")",
            "require('https')",
            "require(\"https\")",
            "require('net')",
            "require(\"net\")",
            "require('tls')",
            "require(\"tls\")",
            "require('dns')",
            "require(\"dns\")",
        ],
    },
    Pattern {
        id: "net-axios",
        kind: FindingKind::Network,
        risk: RiskLevel::Info,
        description: "Uses axios for HTTP requests",
        strings: &[
            "require('axios')",
            "require(\"axios\")",
            "from 'axios'",
            "from \"axios\"",
        ],
    },
    Pattern {
        id: "net-got",
        kind: FindingKind::Network,
        risk: RiskLevel::Info,
        description: "Uses got/node-fetch for HTTP requests",
        strings: &[
            "require('got')",
            "require('node-fetch')",
            "require(\"got\")",
            "require(\"node-fetch\")",
        ],
    },
    Pattern {
        id: "net-socket-connect",
        kind: FindingKind::Network,
        risk: RiskLevel::Medium,
        description: "Creates raw TCP/socket connection",
        strings: &[".connect(", "net.createConnection", "new net.Socket"],
    },
    // ---- FILESYSTEM ----
    Pattern {
        id: "fs-require",
        kind: FindingKind::Filesystem,
        risk: RiskLevel::Low,
        description: "Requires fs module",
        strings: &[
            "require('fs')",
            "require(\"fs\")",
            "require('fs/promises')",
            "require(\"fs/promises\")",
            "require('node:fs')",
            "require(\"node:fs\")",
        ],
    },
    Pattern {
        id: "fs-write-home",
        kind: FindingKind::Filesystem,
        risk: RiskLevel::High,
        description: "Writes to home directory or system paths",
        strings: &[
            "process.env.HOME",
            "os.homedir()",
            "~/.ssh",
            "~/.aws",
            "~/.npmrc",
            "/.ssh/",
            "/.aws/credentials",
        ],
    },
    Pattern {
        id: "fs-read-sensitive",
        kind: FindingKind::Filesystem,
        risk: RiskLevel::High,
        description: "Reads SSH keys, credential paths, or /etc/passwd",
        strings: &[
            "id_rsa",
            "id_ed25519",
            "/.ssh/",
            "/.aws/credentials",
            "/etc/passwd",
            "/etc/shadow",
        ],
    },
    // ---- ENV ACCESS ----
    Pattern {
        id: "env-sensitive",
        kind: FindingKind::EnvAccess,
        risk: RiskLevel::High,
        description: "Accesses sensitive environment variables (tokens/keys/secrets)",
        strings: &[
            "NPM_TOKEN",
            "AWS_SECRET",
            "AWS_ACCESS_KEY",
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "API_KEY",
            "SECRET_KEY",
            "PRIVATE_KEY",
            "DATABASE_URL",
            "CI_TOKEN",
            "SLACK_TOKEN",
            "DISCORD_TOKEN",
        ],
    },
    Pattern {
        id: "env-access",
        kind: FindingKind::EnvAccess,
        risk: RiskLevel::Info,
        description: "Reads environment variables",
        strings: &["process.env"],
    },
    // ---- SUBPROCESS ----
    Pattern {
        id: "subprocess-require",
        kind: FindingKind::Subprocess,
        risk: RiskLevel::Medium,
        description: "Requires child_process module",
        strings: &[
            "require('child_process')",
            "require(\"child_process\")",
            "require('node:child_process')",
            "require(\"node:child_process\")",
        ],
    },
    Pattern {
        id: "subprocess-exec",
        kind: FindingKind::Subprocess,
        risk: RiskLevel::High,
        description: "Executes shell commands",
        strings: &[
            ".execSync(",
            ".spawnSync(",
            ".execFileSync(",
            "child_process.exec(",
            "shelljs",
            "shell.exec(",
            "require('shelljs')",
            "require(\"shelljs\")",
        ],
    },
    // ---- DYNAMIC EXEC ----
    Pattern {
        id: "eval-direct",
        kind: FindingKind::DynamicExec,
        risk: RiskLevel::High,
        description: "Uses eval() for dynamic code execution",
        strings: &["eval(", " eval "],
    },
    Pattern {
        id: "eval-function",
        kind: FindingKind::DynamicExec,
        risk: RiskLevel::High,
        description: "Uses new Function() for dynamic code execution",
        strings: &["new Function(", "new Function ("],
    },
    Pattern {
        id: "eval-vm",
        kind: FindingKind::DynamicExec,
        risk: RiskLevel::High,
        description: "Uses Node.js vm module for dynamic execution",
        strings: &[
            "require('vm')",
            "require(\"vm\")",
            "vm.runInNewContext",
            "vm.runInThisContext",
            "vm.Script",
        ],
    },
    Pattern {
        id: "eval-settimeout-string",
        kind: FindingKind::DynamicExec,
        risk: RiskLevel::High,
        description: "Passes string to setTimeout/setInterval (dynamic exec)",
        strings: &[
            "setTimeout(\"",
            "setInterval(\"",
            "setTimeout('",
            "setInterval('",
        ],
    },
    // ---- OBFUSCATION ----
    // NOTE: raw `Buffer.from(`, `0x`, `\x`, `atob(`, `fromCharCode(` are far too
    // common in legitimate code to flag on their own -- they made express score an
    // F (a parser's `case 0x3c:` and `res.send(Buffer.from('wahoo'))` were called
    // "obfuscation"). The dangerous *forms* (a long hardcoded base64 being decoded,
    // eval(String.fromCharCode(...)), eval() of a long hex string) are detected with
    // context by detect_advanced_obfuscation() in scanner.rs. Keep only low-weight
    // INFO disclosures for the encode/decode primitives here.
    Pattern {
        id: "obfus-atob",
        kind: FindingKind::Obfuscation,
        risk: RiskLevel::Info,
        description: "Uses atob/btoa base64 encoding",
        strings: &["atob(", "btoa("],
    },
    Pattern {
        id: "obfus-charcode",
        kind: FindingKind::Obfuscation,
        risk: RiskLevel::Info,
        description: "Builds strings from char codes",
        strings: &["fromCharCode(", "String.fromCharCode"],
    },
    // ---- DATA EXFILTRATION ----
    Pattern {
        id: "exfil-dns",
        kind: FindingKind::DataExfiltration,
        risk: RiskLevel::Critical,
        description: "Hardcoded DNS-tunnel / out-of-band exfiltration domain",
        // Bare dns.lookup/dns.resolve are normal operations (DB drivers resolve
        // mongodb+srv SRV records, networking libs resolve hosts) -- flagging
        // them as Critical false-positives on legitimate infrastructure packages.
        // Real DNS exfil is caught by the `dns-exfil` pattern (dns + data encoding)
        // and by these attacker-controlled tunnel domains.
        strings: &[
            ".nip.io",
            ".burpcollaborator",
            ".ngrok.io",
            ".oast.",
            ".dnslog.",
        ],
    },
    // ---- CRYPTO MINING ----
    Pattern {
        id: "crypto-miner",
        kind: FindingKind::CryptoMiner,
        risk: RiskLevel::High,
        description: "Possible cryptocurrency mining code",
        strings: &[
            "coinhive",
            "CoinHive",
            "CryptoNight",
            "cryptonight",
            "stratum+tcp://",
            "monero",
            "xmrig",
            "wasm-pack-template",
            "WebAssembly.instantiate",
            "mining",
            "hashrate",
        ],
    },
    // ---- SECOND-STAGE PAYLOAD DOWNLOAD ----
    // Downloads code at runtime then executes it -- the #1 supply-chain evasion technique.
    // Static scanners see nothing malicious in the published package; the real payload
    // is fetched on first install/run from an attacker-controlled server.
    Pattern {
        id: "second-stage-download",
        kind: FindingKind::DynamicExec,
        risk: RiskLevel::Critical,
        description: "Downloads and executes remote code at runtime (second-stage payload)",
        strings: &[
            "eval(require('https')",
            "eval(require(\"https\")",
            "new Function(await",
            "vm.runInContext(await",
            "vm.runInNewContext(await",
            ".then(eval)",
            ".then(r=>eval(",
            ".then(r => eval(",
            "eval(await fetch",
            "eval(await res",
        ],
    },
    // ---- CREDENTIAL HARVESTING ----
    Pattern {
        id: "credential-harvest",
        kind: FindingKind::CredentialHarvest,
        risk: RiskLevel::Critical,
        description: "Reads SSH private keys, browser cookies, or the OS keychain",
        // Reserved for secrets a legitimate package has no reason to touch.
        strings: &[
            ".ssh/id_rsa",
            ".ssh/id_ed25519",
            ".ssh/id_dsa",
            "Library/Application Support/Google/Chrome",
            "Login Data",
            "keychain",
        ],
    },
    // ---- CLOUD / CI CREDENTIAL ACCESS (capability, not an attack by itself) ----
    // Cloud SDKs, CI tooling, and auth libraries legitimately reference these, so
    // this is High (notable), not Critical. Exfiltrating them is what the exfil-*
    // patterns flag as Critical; the popularity trust floor rescues well-known libs.
    Pattern {
        id: "cloud-credential-access",
        kind: FindingKind::CredentialHarvest,
        risk: RiskLevel::High,
        description: "References cloud / CI credential paths or tokens (AWS, GitHub, npm)",
        strings: &[
            ".aws/credentials",
            ".aws/config",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
            "npm_token",
            "NPM_TOKEN",
            ".npmrc",
        ],
    },
    // ---- DATA EXFILTRATION: ENV OVER NETWORK ----
    // Same-file detection only: process.env reads combined with outbound HTTP in one source file.
    // Cross-file combos require dataflow analysis (handled by a separate AST pass, not here).
    Pattern {
        id: "exfil-env-over-network",
        kind: FindingKind::DataExfiltration,
        risk: RiskLevel::High,
        description: "Sends env var contents over network (suspicious exfiltration pattern)",
        // Require very specific patterns: env var value interpolated into a URL or request body
        // Not just any file that happens to use both process.env and fetch
        strings: &[
            "process.env.AWS_SECRET",
            "process.env.GITHUB_TOKEN",
            "process.env.NPM_TOKEN",
            "process.env.CI_JOB_TOKEN",
            "process.env.DATABASE_URL",
            "process.env.SECRET_KEY",
        ],
    },
    // ---- POSTINSTALL SCRIPT ABUSE ----
    Pattern {
        id: "postinstall-heavy",
        kind: FindingKind::InstallScript,
        risk: RiskLevel::High,
        description: "Heavy postinstall lifecycle manipulation (path probing, env inspection)",
        strings: &[
            "npm_lifecycle_event",
            "npm_package_name",
            "npm_lifecycle_script",
            "INIT_CWD",
        ],
    },
    // ---- PROTESTWARE / CONDITIONAL PAYLOAD ----
    // Code that gates destructive/exfil behaviour on locale, timezone, country, or
    // IP geolocation (see node-ipc 2022, peacenotwar 2022).
    Pattern {
        id: "conditional-payload",
        kind: FindingKind::ConditionalPayload,
        risk: RiskLevel::High,
        description: "Conditional payload gated on locale, timezone, or IP geolocation",
        strings: &[
            "Intl.DateTimeFormat",
            "process.env.LANG",
            "process.env.TZ",
            "geoiplookup",
            "ipapi.co",
            "ip-api.com",
            "ipinfo.io",
            "freegeoip",
            "geolocation-db.com",
        ],
    },
    // ---- NEW PATTERN 1: BRACKET NOTATION ----
    // process['env'] / require['child_process'] bypass StaticMemberExpression visitors.
    // String-level pre-filter; AST visitor in analyzer.rs catches the ComputedMemberExpression.
    Pattern {
        id: "bracket-notation",
        kind: FindingKind::BracketNotation,
        risk: RiskLevel::Medium,
        description: "Bracket notation property access used to evade static string detection",
        strings: &[
            "process['env']",
            "process[\"env\"]",
            "require['child_process']",
            "require[\"child_process\"]",
            "process['env']['",
            "process[\"env\"][\"",
        ],
    },
    // ---- NEW PATTERN 3: CI ENVIRONMENT TARGETING ----
    // Attackers check for CI=true to know they're running in a pipeline where tokens are populated.
    Pattern {
        id: "ci-env-targeting",
        kind: FindingKind::CiTargeting,
        risk: RiskLevel::High,
        description: "Reads CI pipeline environment variables (often used to detect and steal tokens)",
        strings: &[
            "process.env.CI",
            "process.env.GITHUB_ACTIONS",
            "process.env.TRAVIS",
            "process.env.CIRCLECI",
            "process.env.GITHUB_TOKEN",
            "process.env.NPM_TOKEN",
            "GITHUB_ACTIONS",
            "TRAVIS_BUILD",
            "CIRCLECI",
        ],
    },
    // ---- NEW PATTERN 5: ENV PATH OVERWRITE ----
    // Overwriting PATH or LD_PRELOAD can redirect system executables to malicious binaries.
    Pattern {
        id: "env-path-overwrite",
        kind: FindingKind::EnvPathOverwrite,
        risk: RiskLevel::High,
        description: "Overwrites process.env.PATH or LD_PRELOAD -- can redirect executables to malicious binaries",
        strings: &[
            "process.env.PATH =",
            "process.env.PATH=",
            "process.env['PATH']",
            "process.env[\"PATH\"]",
            "process.env.LD_PRELOAD",
            "process.env['LD_PRELOAD']",
            "process.env[\"LD_PRELOAD\"]",
            "LD_PRELOAD=",
        ],
    },
    // ---- NEW PATTERN 6: MODULE LOADER PATCH ----
    // Hijacking require() intercepts ALL module loads by any code in the process.
    Pattern {
        id: "module-loader-patch",
        kind: FindingKind::ModuleLoaderPatch,
        risk: RiskLevel::High,
        description: "Patches Node.js module loader (require hijacking) -- can intercept all module loads",
        strings: &[
            "Module._resolveFilename",
            "Module.prototype.require",
            "Module._load",
            "require('module')._resolveFilename",
            "require(\"module\")._resolveFilename",
            "_resolveFilename",
            "prototype.require =",
        ],
    },
    // ---- NEW PATTERN 9: EXFIL DOMAINS ----
    // Hardcoded domains used exclusively for data exfiltration / attacker infrastructure.
    Pattern {
        id: "exfil-domains",
        kind: FindingKind::DataExfiltration,
        risk: RiskLevel::Critical,
        description: "Hardcoded data-exfil domain detected (ngrok, requestbin, pipedream, webhook.site, etc.)",
        strings: &[
            "ngrok.io",
            "ngrok.app",
            "requestbin",
            "pipedream.net",
            "webhook.site",
            "burpcollaborator",
            "duckdns.org",
            "freemyip.com",
        ],
    },
    // ---- DNS EXFILTRATION ----
    // Only flag DNS resolve/lookup calls combined with attacker infrastructure domains,
    // or direct dns.resolve(btoa/Buffer combos (encoding data INTO a hostname).
    Pattern {
        id: "dns-exfil",
        kind: FindingKind::DataExfiltration,
        risk: RiskLevel::Critical,
        description: "DNS exfiltration: data tunnelled through DNS queries to attacker domain",
        strings: &[
            ".burpcollaborator.net",
            ".oastify.com",
            ".interact.sh",
            ".canarytokens.com",
        ],
    },
];

/// Popular package names that are typosquatting targets
/// If a package name is similar to these but NOT these, flag it
pub static POPULAR_PACKAGES: &[&str] = &[
    "react",
    "vue",
    "angular",
    "svelte",
    "express",
    "fastify",
    "koa",
    "hapi",
    "lodash",
    "underscore",
    "ramda",
    "axios",
    "got",
    "node-fetch",
    "superagent",
    "webpack",
    "vite",
    "rollup",
    "esbuild",
    "parcel",
    "typescript",
    "babel",
    "eslint",
    "prettier",
    "jest",
    "mocha",
    "vitest",
    "ava",
    "mongoose",
    "sequelize",
    "prisma",
    "typeorm",
    "socket.io",
    "ws",
    "socket",
    "moment",
    "dayjs",
    "date-fns",
    "dotenv",
    "config",
    "convict",
    "colors",
    "chalk",
    "kleur",
    "picocolors",
    "commander",
    "yargs",
    "minimist",
    "meow",
    "uuid",
    "nanoid",
    "shortid",
    "bcrypt",
    "bcryptjs",
    "jsonwebtoken",
    "passport",
    "multer",
    "busboy",
    "formidable",
    "nodemailer",
    "sendgrid",
    "redis",
    "ioredis",
    "memcached",
    "aws-sdk",
    "@aws-sdk/client-s3",
    "stripe",
    "paypal",
    "sharp",
    "jimp",
    "canvas",
    "cheerio",
    "puppeteer",
    "playwright",
    "cross-env",
    "dotenv-cli",
    "rimraf",
    "mkdirp",
    "glob",
    "minimatch",
    "semver",
    "nvm",
    "node-gyp",
];

/// Check if a package name is a potential typosquat of a popular package.
/// Returns the popular package name if the input is suspiciously similar
/// (edit distance 1-2) but not an exact match.
pub fn check_typosquat(name: &str) -> Option<&'static str> {
    // Skip scoped packages for now (they're less commonly typosquatted)
    // and exact matches.
    let name_lower = name.to_lowercase();
    for popular in POPULAR_PACKAGES {
        if name_lower == *popular {
            continue;
        }
        let distance = edit_distance(&name_lower, popular);
        // Distance 1-2 is suspicious; 0 is exact match (skipped above).
        if (1..=2).contains(&distance) {
            return Some(popular);
        }
    }
    None
}

/// Compute the Levenshtein edit distance between two strings.
fn edit_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let m = a_chars.len();
    let n = b_chars.len();

    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }

    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr = vec![0; n + 1];

    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = if a_chars[i - 1] == b_chars[j - 1] {
                0
            } else {
                1
            };
            curr[j] = (prev[j] + 1).min((curr[j - 1] + 1).min(prev[j - 1] + cost));
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

#[cfg(test)]
mod typosquat_tests {
    use super::*;

    #[test]
    fn detects_simple_typosquat() {
        // "rect" is distance 1 from "react"
        assert_eq!(check_typosquat("rect"), Some("react"));
        // "expres" is distance 1 from "express"
        assert_eq!(check_typosquat("expres"), Some("express"));
    }

    #[test]
    fn ignores_exact_matches() {
        assert_eq!(check_typosquat("react"), None);
        assert_eq!(check_typosquat("express"), None);
    }

    #[test]
    fn ignores_dissimilar_names() {
        assert_eq!(check_typosquat("my-unique-package-12345"), None);
    }
}
