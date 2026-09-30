//! PackageScanner: walks a package directory, analyzes every JS/TS file,
//! and aggregates results into a single AnalysisReport.

use anyhow::Result;
use regex::Regex;
use std::path::Path;
use walkdir::WalkDir;

use crate::analyzer::Analyzer;
use crate::behavior::{self, Behavior, Verdict};
use crate::report::{AnalysisReport, Capabilities, Finding, FindingKind, RiskLevel};

pub struct PackageScanner;

impl PackageScanner {
    /// Scan an extracted package directory (e.g. ~/.oath/store/express@4.18.2/)
    pub fn scan(
        package_name: &str,
        package_version: &str,
        package_dir: &Path,
    ) -> Result<AnalysisReport> {
        let mut all_findings: Vec<Finding> = Vec::new();
        let mut files_scanned = 0usize;
        let mut lines_scanned = 0usize;
        let mut pkg_behavior = Behavior::default();
        let mut install_behavior = Behavior::default();
        let mut package_verdict = Verdict::Info;
        let mut verdict_reasons = Vec::new();
        let mut has_install_script = false;

        // Check for install scripts in package.json first. A manifest that cannot be
        // read or parsed must not silently hide lifecycle code.
        let pkg_json_path = package_dir.join("package.json");
        if pkg_json_path.exists() {
            match std::fs::read_to_string(&pkg_json_path) {
                Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
                    Ok(json) => {
                        let scripts = json.get("scripts");
                        for hook in &["preinstall", "install", "postinstall"] {
                            if let Some(script) = scripts.and_then(|s| s.get(hook))
                                && let Some(cmd) = script.as_str()
                            {
                                has_install_script = true;
                                // The install command itself is often the payload.
                                behavior::scan_install_command(cmd, &mut install_behavior);
                                all_findings.push(Finding {
                                    kind: FindingKind::InstallScript,
                                    risk: RiskLevel::Medium,
                                    message: format!("{hook} script: {cmd}"),
                                    file: "package.json".to_string(),
                                    line: 0,
                                    snippet: Some(cmd.chars().take(120).collect()),
                                });
                            }
                        }
                    }
                    Err(error) => record_incomplete_analysis(
                        &mut all_findings,
                        &mut package_verdict,
                        &mut verdict_reasons,
                        "package.json".to_string(),
                        format!("package.json could not be parsed: {error}"),
                    ),
                },
                Err(error) => record_incomplete_analysis(
                    &mut all_findings,
                    &mut package_verdict,
                    &mut verdict_reasons,
                    "package.json".to_string(),
                    format!("package.json could not be read: {error}"),
                ),
            }
        }

        // Walk all JS/TS files
        for entry in WalkDir::new(package_dir).follow_links(false) {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    let file = error
                        .path()
                        .and_then(|path| path.strip_prefix(package_dir).ok())
                        .unwrap_or_else(|| error.path().unwrap_or(package_dir))
                        .to_string_lossy()
                        .replace('\\', "/");
                    record_incomplete_analysis(
                        &mut all_findings,
                        &mut package_verdict,
                        &mut verdict_reasons,
                        file,
                        format!("package entry could not be inspected: {error}"),
                    );
                    continue;
                }
            };
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

            // Only analyze executable JS/TS source files.
            if !matches!(ext, "js" | "mjs" | "cjs" | "ts" | "tsx") {
                continue;
            }
            // .d.ts/.d.cts/.d.mts are TYPE DECLARATIONS -- no executable code, so they
            // can't be malware, but their JSDoc comments + type signatures trip the
            // string heuristics (the bson ".d.ts comment -> crypto mining" FP). Skip.
            if let Some(name) = path.file_name().and_then(|n| n.to_str())
                && (name.ends_with(".d.ts") || name.ends_with(".d.cts") || name.ends_with(".d.mts"))
            {
                continue;
            }

            let relative_path = path
                .strip_prefix(package_dir)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");

            let bytes = match std::fs::read(path) {
                Ok(bytes) => bytes,
                Err(error) => {
                    record_incomplete_analysis(
                        &mut all_findings,
                        &mut package_verdict,
                        &mut verdict_reasons,
                        relative_path,
                        format!("executable source could not be read: {error}"),
                    );
                    continue;
                }
            };
            let source = match String::from_utf8(bytes) {
                Ok(source) => source,
                Err(error) => {
                    let invalid_at = error.utf8_error().valid_up_to();
                    record_incomplete_analysis(
                        &mut all_findings,
                        &mut package_verdict,
                        &mut verdict_reasons,
                        relative_path.clone(),
                        format!(
                            "executable source is not valid UTF-8 at byte {invalid_at}; scanned with lossy decoding"
                        ),
                    );
                    String::from_utf8_lossy(error.as_bytes()).into_owned()
                }
            };

            lines_scanned += source.lines().count();
            files_scanned += 1;

            // AST-first behavioral facts (capabilities + dangerous combinations).
            let file_behavior = behavior::analyze_file(&source, &relative_path);
            let (file_verdict, file_reasons) = behavior::verdict(&file_behavior, false);
            merge_verdict(
                &mut package_verdict,
                &mut verdict_reasons,
                file_verdict,
                file_reasons,
            );
            pkg_behavior.merge(&file_behavior);

            // Obfuscation detection post-pass on already-read source
            let obfuscation_findings = detect_obfuscation(&source, &relative_path);
            all_findings.extend(obfuscation_findings);

            // Advanced obfuscation / malware detection (Feature 2)
            let advanced_findings = detect_advanced_obfuscation(&source, &relative_path);
            all_findings.extend(advanced_findings);

            let mut analyzer = Analyzer::new(source, relative_path);
            analyzer.analyze()?;
            if analyzer
                .findings
                .iter()
                .any(|finding| finding.kind == FindingKind::AnalysisIncomplete)
            {
                merge_verdict(
                    &mut package_verdict,
                    &mut verdict_reasons,
                    Verdict::Warn,
                    vec![incomplete_analysis_reason().to_string()],
                );
            }
            all_findings.extend(analyzer.findings);
        }

        // Deduplicate findings by (kind, file, line)
        all_findings.dedup_by(|a, b| a.kind == b.kind && a.file == b.file && a.line == b.line);

        // Aggregate capabilities (from AST behavior + legacy findings)
        let mut capabilities = Capabilities::default();
        for f in &all_findings {
            match f.kind {
                FindingKind::Network | FindingKind::DataExfiltration => capabilities.network = true,
                FindingKind::Filesystem => capabilities.filesystem = true,
                FindingKind::EnvAccess => capabilities.env_access = true,
                FindingKind::Subprocess => capabilities.subprocess = true,
                FindingKind::DynamicExec => capabilities.dynamic_exec = true,
                FindingKind::InstallScript => capabilities.has_install_scripts = true,
                _ => {}
            }
        }
        capabilities.network |= pkg_behavior.net;
        capabilities.filesystem |= pkg_behavior.fs;
        capabilities.subprocess |= pkg_behavior.subprocess;
        capabilities.env_access |= pkg_behavior.env_read;
        capabilities.dynamic_exec |= pkg_behavior.code_exec;
        capabilities.has_install_scripts |= has_install_script;

        pkg_behavior.merge(&install_behavior);
        let (install_verdict, install_reasons) =
            behavior::verdict(&install_behavior, has_install_script);
        merge_verdict(
            &mut package_verdict,
            &mut verdict_reasons,
            install_verdict,
            install_reasons,
        );

        // Overall risk is driven by per-file AST-first behavioral verdicts, not
        // max of substring findings (which flagged express grade-F for merely
        // using fs/http/process.env), and not by unrelated capabilities merged
        // from different files. Only correlated dangerous combinations escalate.
        let overall_risk = match package_verdict {
            Verdict::Block => RiskLevel::Critical,
            Verdict::Warn => RiskLevel::High,
            Verdict::Info => RiskLevel::Info,
        };

        Ok(AnalysisReport {
            package_name: package_name.to_string(),
            package_version: package_version.to_string(),
            overall_risk,
            findings: all_findings,
            files_scanned,
            lines_scanned,
            capabilities,
            verdict_reasons,
        })
    }
}

fn incomplete_analysis_reason() -> &'static str {
    "analysis incomplete; one or more executable package inputs require review"
}

fn record_incomplete_analysis(
    findings: &mut Vec<Finding>,
    package_verdict: &mut Verdict,
    verdict_reasons: &mut Vec<String>,
    file: String,
    message: String,
) {
    findings.push(Finding {
        kind: FindingKind::AnalysisIncomplete,
        risk: RiskLevel::High,
        message,
        file,
        line: 0,
        snippet: None,
    });
    merge_verdict(
        package_verdict,
        verdict_reasons,
        Verdict::Warn,
        vec![incomplete_analysis_reason().to_string()],
    );
}

fn merge_verdict(
    current: &mut Verdict,
    current_reasons: &mut Vec<String>,
    next: Verdict,
    next_reasons: Vec<String>,
) {
    let rank = |verdict| match verdict {
        Verdict::Info => 0,
        Verdict::Warn => 1,
        Verdict::Block => 2,
    };
    if rank(next) > rank(*current) {
        *current = next;
    }
    for reason in next_reasons {
        if !current_reasons.contains(&reason) {
            current_reasons.push(reason);
        }
    }
}

/// Detect obfuscation patterns in source code.
/// Returns findings for minification, hex encoding, char code abuse, and short variable names.
fn detect_obfuscation(source: &str, relative_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lines: Vec<&str> = source.lines().collect();
    let line_count = lines.len();

    // 1. Minification detection: avg line length > 500 AND > 50 lines
    if line_count > 50 {
        let total_chars: usize = lines.iter().map(|l| l.len()).sum();
        let avg_line_len = total_chars / line_count;
        if avg_line_len > 500 {
            let is_vendor =
                relative_path.contains("node_modules") || relative_path.contains("vendor/");
            let (risk, desc) = if is_vendor {
                (RiskLevel::Info, "Minified vendor bundle detected")
            } else {
                (
                    RiskLevel::Medium,
                    "Minified source code detected (not vendor)",
                )
            };
            findings.push(Finding {
                kind: FindingKind::Obfuscation,
                risk,
                message: format!(
                    "{}: avg line length {} chars across {} lines",
                    desc, avg_line_len, line_count
                ),
                file: relative_path.to_string(),
                line: 1,
                snippet: Some(lines[0].chars().take(120).collect()),
            });
        }
    }

    // 2. Hex encoding density: >20% of string content matches \x[0-9a-f]{2}
    let hex_re = Regex::new(r"\\x[0-9a-fA-F]{2}").unwrap();
    let string_re = Regex::new(r#"(?:"([^"\\]|\\.)*"|'([^'\\]|\\.)*')"#).unwrap();
    let mut total_string_len = 0usize;
    let mut hex_match_len = 0usize;
    for mat in string_re.find_iter(source) {
        let s = mat.as_str();
        total_string_len += s.len();
        for hex_mat in hex_re.find_iter(s) {
            hex_match_len += hex_mat.as_str().len();
        }
    }
    if total_string_len > 100 {
        let hex_ratio = hex_match_len as f64 / total_string_len as f64;
        if hex_ratio > 0.20 {
            findings.push(Finding {
                kind: FindingKind::Obfuscation,
                risk: RiskLevel::High,
                message: format!(
                    "High hex encoding density: {:.1}% of string content is \\\\xNN encoded",
                    hex_ratio * 100.0
                ),
                file: relative_path.to_string(),
                line: 1,
                snippet: None,
            });
        }
    }

    // 3. Char-code building: many String.fromCharCode in non-test code. Read-only
    //    charCodeAt and plain fromCharCode are ubiquitous in legit parsers,
    //    formatters and encoders (prettier alone has dozens), so this is
    //    INFORMATIONAL only -- it never penalizes the score. The genuinely
    //    dangerous form, eval/require(String.fromCharCode(...)), is caught as
    //    Critical in detect_advanced_obfuscation below.
    if !relative_path.contains("test") && !relative_path.contains("spec") {
        let from_char_code_count = source.matches("String.fromCharCode").count();
        if from_char_code_count > 25 {
            findings.push(Finding {
                kind: FindingKind::Obfuscation,
                risk: RiskLevel::Info,
                message: format!(
                    "Builds {} strings from char codes (informational)",
                    from_char_code_count
                ),
                file: relative_path.to_string(),
                line: 1,
                snippet: None,
            });
        }
    }

    // 4. Variable name entropy: avg identifier length < 2 across > 100 identifiers
    let ident_re = Regex::new(r"\b[a-zA-Z_$][a-zA-Z0-9_$]*\b").unwrap();
    let keywords: &[&str] = &[
        "var",
        "let",
        "const",
        "function",
        "return",
        "if",
        "else",
        "for",
        "while",
        "do",
        "switch",
        "case",
        "break",
        "continue",
        "new",
        "this",
        "typeof",
        "instanceof",
        "void",
        "delete",
        "in",
        "of",
        "try",
        "catch",
        "finally",
        "throw",
        "class",
        "extends",
        "import",
        "export",
        "default",
        "from",
        "async",
        "await",
        "yield",
        "true",
        "false",
        "null",
        "undefined",
    ];
    let mut ident_lengths: Vec<usize> = Vec::new();
    for mat in ident_re.find_iter(source) {
        let word = mat.as_str();
        if !keywords.contains(&word) && word.len() <= 20 {
            ident_lengths.push(word.len());
        }
    }
    if ident_lengths.len() > 100 {
        let total_len: usize = ident_lengths.iter().sum();
        let avg_len = total_len as f64 / ident_lengths.len() as f64;
        if avg_len < 2.0 {
            findings.push(Finding {
                kind: FindingKind::Obfuscation,
                risk: RiskLevel::Medium,
                message: format!(
                    "Short variable names: avg identifier length {:.1} chars across {} identifiers",
                    avg_len,
                    ident_lengths.len()
                ),
                file: relative_path.to_string(),
                line: 1,
                snippet: None,
            });
        }
    }

    findings
}

/// Detect advanced obfuscation patterns added in Feature 2.
/// Scores: base64 payload +30, dynamic require +25, hex string exec +40,
/// env exfiltration combo +35, crypto wallet patterns +20 per occurrence.
pub fn detect_advanced_obfuscation(source: &str, relative_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // 1. Base64 payload detection
    // Buffer.from('...', 'base64') or atob(...) with strings > 50 chars
    // The high-signal discriminator is the explicit base64 decode (the `'base64'`
    // arg / atob), not "Buffer.from exists". A hardcoded base64 blob of even
    // moderate length being decoded is what's suspicious -- so we key on the
    // decode form, not raw `Buffer.from(`, which every package uses.
    let b64_buf_re =
        Regex::new(r#"Buffer\.from\(\s*['"]([A-Za-z0-9+/=]{24,})['"]\s*,\s*['"]base64['"]\s*\)"#)
            .unwrap();
    let atob_re = Regex::new(r#"atob\(\s*['"]([A-Za-z0-9+/=]{24,})['"]\s*\)"#).unwrap();

    let b64_count = b64_buf_re.find_iter(source).count() + atob_re.find_iter(source).count();

    for _ in 0..b64_count {
        findings.push(Finding {
            kind: FindingKind::Obfuscation,
            // Decoding a hardcoded base64 blob is moderately suspicious, but legit
            // packages embed base64 (wasm, fonts, certs, source maps), so Medium --
            // not High. The dangerous form, eval/Function/require(atob(...)), is
            // Critical via the decode-then-execute combos below.
            risk: RiskLevel::Medium,
            message:
                "Base64 payload detected: Buffer.from(..., 'base64') or atob() with long string"
                    .to_string(),
            file: relative_path.to_string(),
            line: 1,
            snippet: None,
        });
    }

    // 2. Dynamic require with a computed module name. `require(`./x/${y}`)` template
    //    paths and plugin loaders are extremely common in legit code (prettier loads
    //    its plugins this way), so on their own these are a WEAK (Low) signal -- we
    //    drop the benign template-literal shape entirely and keep only the classic
    //    name-splitting shapes (array-join / string-concat) used to evade scanners.
    //    The high-signal form -- require() of a DECODED string -- is Critical in the
    //    decode-then-execute combos below.
    let dyn_req_patterns: &[&str] = &[
        r"require\s*\(\s*\[", // require([...].join) -- name assembled from an array
        r"require\s*\('[^']*'\s*\+", // require('str' + ...) -- split string name
        r#"require\s*\("[^"]*"\s*\+"#, // require("str" + ...)
    ];
    for pat in dyn_req_patterns {
        let re = Regex::new(pat).unwrap();
        let count = re.find_iter(source).count();
        for _ in 0..count {
            findings.push(Finding {
                kind: FindingKind::Obfuscation,
                risk: RiskLevel::Low,
                message: "Dynamic require with a computed/concatenated module name".to_string(),
                file: relative_path.to_string(),
                line: 1,
                snippet: None,
            });
        }
    }

    // 3. Hex string execution: eval(String.fromCharCode(...)) or long hex strings in eval
    let eval_charcode_re = Regex::new(r"eval\s*\(\s*String\.fromCharCode\s*\(").unwrap();
    let eval_hex_re = Regex::new(r#"eval\s*\(\s*['"](?:\\x[0-9a-fA-F]{2}){20,}['"]\s*\)"#).unwrap();

    let hex_exec_count =
        eval_charcode_re.find_iter(source).count() + eval_hex_re.find_iter(source).count();

    for _ in 0..hex_exec_count {
        findings.push(Finding {
            kind: FindingKind::Obfuscation,
            risk: RiskLevel::Critical,
            message: "Hex string execution: eval(String.fromCharCode(...)) or eval() with hex-encoded string".to_string(),
            file: relative_path.to_string(),
            line: 1,
            snippet: None,
        });
    }

    // 4. Environment variable exfiltration: reading SENSITIVE env (or enumerating
    //    the whole environment) together with a real outbound sink in one file.
    //    The old check fired on any `process.env` + any `.get(`/`.post(`, so every
    //    web framework reading NODE_ENV and defining app.get/app.post was flagged
    //    HIGH. Real exfil reads secrets (or all of process.env) and ships them out.
    let sensitive_env = source.contains("process.env.NPM_TOKEN")
        || source.contains("process.env.AWS")
        || source.contains("process.env.GITHUB_TOKEN")
        || source.contains("process.env.GH_TOKEN")
        || source.contains("process.env.SECRET")
        || source.contains("process.env.PRIVATE")
        || source.contains("process.env.TOKEN")
        || source.contains("process.env.PASSWORD")
        // whole-environment capture (JSON.stringify(process.env), {...process.env}, Object.keys(process.env))
        || source.contains("stringify(process.env")
        || source.contains("...process.env")
        || source.contains("keys(process.env")
        || source.contains("entries(process.env")
        || source.contains("assign({}, process.env");

    let outbound_sink = source.contains("require('http')")
        || source.contains("require(\"http\")")
        || source.contains("require('https')")
        || source.contains("require(\"https\")")
        || source.contains("fetch(")
        || source.contains("axios")
        || source.contains(".request(")
        || source.contains("net.connect")
        || source.contains("dns.");

    if sensitive_env && outbound_sink {
        findings.push(Finding {
            kind: FindingKind::DataExfiltration,
            risk: RiskLevel::High,
            message: "Possible secret exfiltration: sensitive environment variables read alongside an outbound network call".to_string(),
            file: relative_path.to_string(),
            line: 1,
            snippet: None,
        });
    }

    // 4b. Decode-then-execute combos: a decode primitive (base64/charcode) feeding
    //     straight into a code-exec sink (eval/Function/require). These are near
    //     zero-false-positive malware signatures -- legitimate code essentially
    //     never eval()s decoded bytes or require()s a char-code-built name. This
    //     restores (and sharpens) the signal lost when the loose atob/charcode/
    //     Buffer.from patterns were downgraded to Info, with full context.
    let compact: String = source.chars().filter(|c| !c.is_whitespace()).collect();
    let decode_exec: &[&str] = &[
        "eval(atob(",
        "eval(Buffer.from(",
        "eval(String.fromCharCode(",
        "Function(atob(",
        "Function(Buffer.from(",
        "Function(String.fromCharCode(",
        "require(atob(",
        "require(Buffer.from(",
        "require(String.fromCharCode(",
    ];
    for pat in decode_exec {
        if compact.contains(pat) {
            findings.push(Finding {
                kind: FindingKind::DynamicExec,
                risk: RiskLevel::Critical,
                message: "Decoded payload executed: a base64/charcode decode feeds directly into eval/Function/require".to_string(),
                file: relative_path.to_string(),
                line: 1,
                snippet: None,
            });
        }
    }

    // 5. Cryptocurrency wallet patterns
    // Ethereum: 0x[0-9a-f]{40}
    // Bitcoin: [13][a-km-zA-HJ-NP-Z1-9]{25,34}
    let eth_wallet_re = Regex::new(r"\b0x[0-9a-fA-F]{40}\b").unwrap();
    let btc_wallet_re = Regex::new(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b").unwrap();

    let wallet_count =
        eth_wallet_re.find_iter(source).count() + btc_wallet_re.find_iter(source).count();

    for _ in 0..wallet_count {
        findings.push(Finding {
            kind: FindingKind::CryptoMiner,
            risk: RiskLevel::Medium,
            message: "Cryptocurrency wallet address detected (Bitcoin/Ethereum pattern)"
                .to_string(),
            file: relative_path.to_string(),
            line: 1,
            snippet: None,
        });
    }

    findings
}
