//! package.json read/write that preserves what npm preserves.
//!
//! npm's `@npmcli/package-json` keeps the file's key order, detects the
//! indentation and line ending in use, and always ends the file with one
//! newline. Oath rewrites package.json through this module so an `add` or
//! `remove` changes only the dependency sections npm would change.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// A parsed package.json together with the formatting needed to write it back
/// without gratuitous diffs.
#[derive(Debug, Clone)]
pub struct PackageJsonDocument {
    pub path: PathBuf,
    pub value: serde_json::Value,
    indent: String,
    newline: String,
}

impl PackageJsonDocument {
    /// Parse the package.json at `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("no package.json found at {}", path.display()))?;
        let value: serde_json::Value = serde_json::from_str(&text)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        let (indent, newline) = detect_format(&text);
        Ok(Self {
            path: path.to_path_buf(),
            value,
            indent,
            newline,
        })
    }

    /// Parse the package.json at `path`, or start a new document with
    /// `default_value` and npm's default formatting when the file is missing.
    pub fn load_or_default(path: &Path, default_value: serde_json::Value) -> Result<Self> {
        if path.exists() {
            Self::load(path)
        } else {
            Ok(Self {
                path: path.to_path_buf(),
                value: default_value,
                indent: "  ".into(),
                newline: "\n".into(),
            })
        }
    }

    /// Serialize exactly as npm does: `JSON.stringify(content, null, indent)`
    /// plus a trailing newline, with every newline rewritten to the file's own
    /// line ending.
    pub fn render(&self) -> Result<String> {
        let mut buffer = Vec::new();
        let formatter = serde_json::ser::PrettyFormatter::with_indent(self.indent.as_bytes());
        let mut serializer = serde_json::Serializer::with_formatter(&mut buffer, formatter);
        serde::Serialize::serialize(&self.value, &mut serializer)
            .context("failed to serialize package.json")?;
        let mut text = String::from_utf8(buffer).context("package.json is not UTF-8")?;
        text.push('\n');
        if self.newline != "\n" {
            text = text.replace('\n', &self.newline);
        }
        Ok(text)
    }

    /// Write the document back, only touching the file when its content changed.
    pub fn save(&self) -> Result<()> {
        let rendered = self.render()?;
        if let Ok(existing) = std::fs::read_to_string(&self.path)
            && existing.trim() == rendered.trim()
        {
            return Ok(());
        }
        std::fs::write(&self.path, rendered)
            .with_context(|| format!("failed to write {}", self.path.display()))
    }
}

/// Mirror json-parse-even-better-errors: the indent is the whitespace that
/// precedes the first key after the opening brace, and the newline is the
/// first line break found there. A file with no line break after `{` has no
/// indentation at all; npm then writes it compactly too.
fn detect_format(text: &str) -> (String, String) {
    let trimmed = text.trim_start();
    let Some(rest) = trimmed
        .strip_prefix('{')
        .or_else(|| trimmed.strip_prefix('['))
    else {
        return ("  ".into(), "\n".into());
    };
    let body = rest.trim_start_matches([' ', '\t']);
    if !body.starts_with(['\n', '\r']) {
        // `{}` or `{"name": ...` on one line: npm's parser leaves the indent
        // undefined for an empty object and empty for an inline one.
        let is_empty_object = body.trim_start().starts_with(['}', ']']);
        return (if is_empty_object { "  " } else { "" }.into(), "\n".into());
    }
    let newline = if body.starts_with("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let after_newline = body.trim_start_matches(['\n', '\r']);
    let indent: String = after_newline
        .chars()
        .take_while(|c| *c == ' ' || *c == '\t')
        .collect();
    (indent, newline.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_two_space_indent_and_lf() {
        assert_eq!(
            detect_format("{\n  \"name\": \"a\"\n}\n"),
            ("  ".to_string(), "\n".to_string())
        );
    }

    #[test]
    fn detects_tabs_and_crlf() {
        assert_eq!(
            detect_format("{\r\n\t\"name\": \"a\"\r\n}\r\n"),
            ("\t".to_string(), "\r\n".to_string())
        );
    }

    #[test]
    fn detects_four_spaces() {
        assert_eq!(
            detect_format("{\n    \"name\": \"a\"\n}"),
            ("    ".to_string(), "\n".to_string())
        );
    }

    #[test]
    fn inline_object_has_no_indent_and_empty_object_uses_default() {
        assert_eq!(detect_format("{\"name\":\"a\"}"), ("".into(), "\n".into()));
        assert_eq!(detect_format("{}\n"), ("  ".into(), "\n".into()));
    }

    #[test]
    fn round_trip_preserves_key_order_indent_and_trailing_newline() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("package.json");
        let original = "{\n    \"name\": \"demo\",\n    \"zeta\": 1,\n    \"scripts\": {\n        \"test\": \"node test.js\"\n    },\n    \"alpha\": true\n}\n";
        std::fs::write(&path, original).unwrap();
        let mut doc = PackageJsonDocument::load(&path).unwrap();
        doc.value["dependencies"] = serde_json::json!({ "is-number": "^7.0.0" });
        doc.save().unwrap();
        let written = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            written,
            "{\n    \"name\": \"demo\",\n    \"zeta\": 1,\n    \"scripts\": {\n        \"test\": \"node test.js\"\n    },\n    \"alpha\": true,\n    \"dependencies\": {\n        \"is-number\": \"^7.0.0\"\n    }\n}\n"
        );
    }

    #[test]
    fn unchanged_content_is_not_rewritten() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("package.json");
        std::fs::write(&path, "{\n  \"name\": \"demo\"\n}\n").unwrap();
        let before = std::fs::metadata(&path).unwrap().modified().unwrap();
        let doc = PackageJsonDocument::load(&path).unwrap();
        doc.save().unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            before
        );
    }
}
