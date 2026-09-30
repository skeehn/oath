//! Core analyzer: runs pattern matching on JS/TS source
//!
//! Two-phase approach:
//! 1. Fast string scan -- catches most patterns (require, eval, fetch, etc.)
//! 2. OXC AST walk -- catches obfuscated/indirect patterns (env exfil combos)

use anyhow::Result;

use oxc::allocator::Allocator;
use oxc::ast::ast::{CallExpression, Expression, MemberExpression};
use oxc::ast_visit::Visit;
use oxc::parser::Parser;
use oxc::span::SourceType;

use crate::patterns::PATTERNS;
use crate::report::{Capabilities, Finding, FindingKind, RiskLevel};

pub struct Analyzer {
    pub findings: Vec<Finding>,
    pub capabilities: Capabilities,
    source: String,
    file_path: String,
}

impl Analyzer {
    pub fn new(source: String, file_path: String) -> Self {
        Self {
            findings: Vec::new(),
            capabilities: Capabilities::default(),
            source,
            file_path,
        }
    }

    pub fn analyze(&mut self) -> Result<()> {
        self.string_scan();
        self.ast_scan()?;
        self.update_capabilities();
        Ok(())
    }

    fn string_scan(&mut self) {
        for pattern in PATTERNS {
            for needle in pattern.strings {
                if let Some(pos) = self.source.find(needle) {
                    let line = line_number(&self.source, pos);
                    let already = self
                        .findings
                        .iter()
                        .any(|f| f.kind == pattern.kind && f.line == line);
                    if !already {
                        let snippet = extract_line(&self.source, line);
                        self.findings.push(Finding {
                            kind: pattern.kind.clone(),
                            risk: pattern.risk.clone(),
                            message: pattern.description.to_string(),
                            file: self.file_path.clone(),
                            line,
                            snippet: Some(snippet),
                        });
                    }
                    break;
                }
            }
        }
    }

    fn ast_scan(&mut self) -> Result<()> {
        let allocator = Allocator::default();
        let source_type = infer_source_type(&self.file_path);
        let result = Parser::new(&allocator, &self.source, source_type).parse();

        if !result.diagnostics.is_empty() {
            let diagnostic_count = result.diagnostics.len();
            let first_diagnostic = result
                .diagnostics
                .first()
                .map(ToString::to_string)
                .unwrap_or_else(|| "unknown parser error".to_string());
            self.findings.push(Finding {
                kind: FindingKind::AnalysisIncomplete,
                risk: RiskLevel::High,
                message: format!(
                    "JavaScript/TypeScript parser reported {diagnostic_count} error(s); analysis may be incomplete: {first_diagnostic}"
                ),
                file: self.file_path.clone(),
                line: 0,
                snippet: None,
            });
        }

        if result.program.body.is_empty() {
            return Ok(());
        }

        let mut visitor = AstVisitor {
            findings: &mut self.findings,
            source: &self.source,
            file_path: &self.file_path,
        };
        visitor.visit_program(&result.program);
        Ok(())
    }

    fn update_capabilities(&mut self) {
        for f in &self.findings {
            match f.kind {
                FindingKind::Network | FindingKind::DataExfiltration => {
                    self.capabilities.network = true
                }
                FindingKind::Filesystem => self.capabilities.filesystem = true,
                FindingKind::EnvAccess => self.capabilities.env_access = true,
                FindingKind::Subprocess => self.capabilities.subprocess = true,
                FindingKind::DynamicExec => self.capabilities.dynamic_exec = true,
                FindingKind::InstallScript => self.capabilities.has_install_scripts = true,
                _ => {}
            }
        }
    }
}

struct AstVisitor<'a> {
    findings: &'a mut Vec<Finding>,
    source: &'a str,
    file_path: &'a str,
}

impl<'a> AstVisitor<'a> {
    fn push(&mut self, kind: FindingKind, risk: RiskLevel, msg: &str, line: u32, snippet: &str) {
        if self
            .findings
            .iter()
            .any(|f| f.kind == kind && f.line == line)
        {
            return;
        }
        self.findings.push(Finding {
            kind,
            risk,
            message: msg.to_string(),
            file: self.file_path.to_string(),
            line,
            snippet: Some(snippet.to_string()),
        });
    }

    fn offset_to_line(&self, offset: u32) -> u32 {
        line_number(self.source, offset as usize)
    }

    fn line_snippet(&self, offset: u32) -> String {
        extract_line(self.source, self.offset_to_line(offset))
    }

    // Detect exfiltration: fetch(...) + process.env anywhere nearby
    fn check_exfil_combo(&mut self, call: &CallExpression) {
        let start = call.span.start as usize;
        let end = (call.span.end as usize).min(self.source.len());
        let slice = &self.source[start..end];
        if slice.contains("process.env")
            && (slice.contains("POST") || slice.contains("body") || slice.contains("send"))
        {
            let line = self.offset_to_line(call.span.start);
            let snippet = self.line_snippet(call.span.start);
            self.push(
                FindingKind::DataExfiltration,
                RiskLevel::Critical,
                "Sends environment variables over network (likely credential theft)",
                line,
                &snippet,
            );
        }
    }
}

impl<'a> Visit<'a> for AstVisitor<'a> {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        let start = it.span.start;

        match &it.callee {
            Expression::Identifier(id) => {
                if id.name == "eval" {
                    let line = self.offset_to_line(start);
                    let snippet = self.line_snippet(start);
                    self.push(
                        FindingKind::DynamicExec,
                        RiskLevel::High,
                        "Direct eval() -- dynamic code execution",
                        line,
                        &snippet,
                    );
                } else if id.name == "fetch" {
                    self.check_exfil_combo(it);
                }
            }
            Expression::StaticMemberExpression(m) => {
                let prop = m.property.name.as_str();
                // Buffer.from(..., 'base64') obfuscation
                if prop == "from"
                    && let Expression::Identifier(obj) = &m.object
                    && obj.name == "Buffer"
                    && it.arguments.len() >= 2
                {
                    // Clamp the window end down to a UTF-8 char boundary; a fixed
                    // +80 byte offset can land inside a multi-byte char (e.g.
                    // non-ASCII source) and panic the slice.
                    let mut end = (start as usize + 80).min(self.source.len());
                    while end > start as usize && !self.source.is_char_boundary(end) {
                        end -= 1;
                    }
                    let slice = &self.source[start as usize..end];
                    if slice.contains("base64") || slice.contains("hex") {
                        let line = self.offset_to_line(start);
                        let snippet = self.line_snippet(start);
                        self.push(
                            FindingKind::Obfuscation,
                            RiskLevel::Medium,
                            "Buffer.from() with base64/hex (obfuscation pattern)",
                            line,
                            &snippet,
                        );
                    }
                }
                // new Function() via .constructor
                if prop == "constructor"
                    && let Expression::Identifier(obj) = &m.object
                    && obj.name == "Function"
                {
                    let line = self.offset_to_line(start);
                    let snippet = self.line_snippet(start);
                    self.push(
                        FindingKind::DynamicExec,
                        RiskLevel::High,
                        "Function.constructor() -- dynamic code execution",
                        line,
                        &snippet,
                    );
                }
            }
            _ => {}
        }

        // Walk children
        oxc::ast_visit::walk::walk_call_expression(self, it);
    }

    fn visit_member_expression(&mut self, it: &MemberExpression<'a>) {
        if let MemberExpression::StaticMemberExpression(m) = it
            && let Expression::Identifier(obj) = &m.object
            && obj.name == "process"
            && m.property.name == "env"
        {
            let line = self.offset_to_line(m.span.start);
            let snippet = self.line_snippet(m.span.start);
            self.push(
                FindingKind::EnvAccess,
                RiskLevel::Info,
                "Reads process.env",
                line,
                &snippet,
            );
        }
        oxc::ast_visit::walk::walk_member_expression(self, it);
    }
}

fn infer_source_type(path: &str) -> SourceType {
    if path.ends_with(".ts") || path.ends_with(".tsx") {
        SourceType::ts()
    } else if path.ends_with(".mjs") {
        SourceType::mjs()
    } else {
        SourceType::cjs()
    }
}

fn line_number(source: &str, byte_offset: usize) -> u32 {
    source[..byte_offset.min(source.len())]
        .chars()
        .filter(|&c| c == '\n')
        .count() as u32
        + 1
}

pub fn extract_line(source: &str, line: u32) -> String {
    source
        .lines()
        .nth(line.saturating_sub(1) as usize)
        .unwrap_or("")
        .trim()
        .chars()
        .take(120)
        .collect()
}
