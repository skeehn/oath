//! Launching the command an exec resolved to: locating it on the bin paths,
//! reading its shebang so non-JavaScript bins run with their own
//! interpreter, building the environment npm's run-script gives an `npx`
//! command, and detecting CI and TTYs for npm's prompt rule.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

/// ci-info's `isCI`: `CI` is not "false" and any well-known CI variable is
/// present.
pub fn is_ci() -> bool {
    let env = |name: &str| std::env::var_os(name).is_some_and(|v| !v.is_empty());
    if std::env::var("CI").is_ok_and(|v| v == "false") {
        return false;
    }
    const GENERIC: [&str; 9] = [
        "BUILD_ID",
        "BUILD_NUMBER",
        "CI",
        "CI_APP_ID",
        "CI_BUILD_ID",
        "CI_BUILD_NUMBER",
        "CI_NAME",
        "CONTINUOUS_INTEGRATION",
        "RUN_ID",
    ];
    const VENDORS: [&str; 52] = [
        "AGOLA_GIT_REF",
        "ALPIC_HOST",
        "AC_APPCIRCLE",
        "APPVEYOR",
        "CODEBUILD_BUILD_ARN",
        "TF_BUILD",
        "bamboo_planKey",
        "BITBUCKET_COMMIT",
        "BITRISE_IO",
        "BUDDY_WORKSPACE_ID",
        "BUILDKITE",
        "CIRCLECI",
        "CIRRUS_CI",
        "CF_PAGES",
        "WORKERS_CI",
        "CF_BUILD_ID",
        "CM_BUILD_ID",
        "DRONE",
        "DSARI",
        "EARTHLY_CI",
        "EAS_BUILD",
        "GERRIT_PROJECT",
        "GITEA_ACTIONS",
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "GO_PIPELINE_LABEL",
        "BUILDER_OUTPUT",
        "HARNESS_BUILD_ID",
        "HUDSON_URL",
        "JENKINS_URL",
        "LAYERCI",
        "MAGNUM",
        "NETLIFY",
        "NEVERCODE",
        "PROW_JOB_ID",
        "RELEASE_BUILD_ID",
        "RENDER",
        "SAILCI",
        "SCREWDRIVER",
        "SEMAPHORE",
        "STRIDER",
        "TASK_ID",
        "TEAMCITY_VERSION",
        "TRAVIS",
        "VELA",
        "NOW_BUILDER",
        "VERCEL",
        "APPCENTER_BUILD_ID",
        "CI_XCODE_PROJECT",
        "XCS",
        "HEROKU_TEST_RUN_ID",
        "SOURCEHUT",
    ];
    GENERIC.iter().chain(VENDORS.iter()).any(|name| env(name))
}

/// libnpmexec's `noTTY`: stdin is not a terminal.
pub fn stdin_is_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}

/// npm's local prefix: the nearest ancestor of `cwd` (including itself) that
/// holds a `package.json` or a `node_modules` directory, else `cwd`.
pub fn find_local_prefix(cwd: &Path) -> PathBuf {
    for dir in cwd.ancestors() {
        if dir.join("package.json").is_file() || dir.join("node_modules").is_dir() {
            return dir.to_path_buf();
        }
    }
    cwd.to_path_buf()
}

/// libnpmexec's `localFileExists`: walk up from `dir` looking for
/// `node_modules/.bin/<cmd>`, returning that `.bin` directory.
pub fn walk_up_bin(dir: &Path, cmd: &str) -> Option<PathBuf> {
    for ancestor in dir.ancestors() {
        let bin_dir = ancestor.join("node_modules").join(".bin");
        if command_in_dir(&bin_dir, cmd).is_some() {
            return Some(bin_dir);
        }
    }
    None
}

/// The bin-file candidates for `cmd` in one directory, in the order a
/// shell (or on Windows, PATHEXT) would try them. Never consults `PATH`.
pub fn command_in_dir(dir: &Path, cmd: &str) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if cfg!(windows) {
        let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into());
        for ext in pathext.split(';').filter(|e| !e.is_empty()) {
            candidates.push(dir.join(format!("{cmd}{}", ext.to_ascii_lowercase())));
        }
    }
    candidates.push(dir.join(cmd));
    candidates.into_iter().find(|path| path.is_file())
}

/// Find `cmd` the way a shell would with `bin_dirs` prepended to PATH. A
/// command containing a path separator must be an explicit relative or
/// absolute path; bare names never escape their directory.
pub fn find_command(cmd: &str, bin_dirs: &[PathBuf], cwd: &Path) -> Result<PathBuf> {
    if cmd.contains('/') || cmd.contains('\\') {
        let explicit = cmd.starts_with("./")
            || cmd.starts_with("../")
            || cmd.starts_with('/')
            || cmd.starts_with(".\\")
            || cmd.starts_with("..\\")
            || Path::new(cmd).is_absolute();
        if !explicit {
            bail!("refusing to run \"{cmd}\": bin names cannot contain path separators");
        }
        let path = cwd.join(cmd);
        if path.is_file() {
            return Ok(path);
        }
        bail!("command not found: {cmd}");
    }
    let path_env = std::env::var_os("PATH").unwrap_or_default();
    let dirs = bin_dirs
        .iter()
        .cloned()
        .chain(std::env::split_paths(&path_env));
    for dir in dirs {
        if let Some(found) = command_in_dir(&dir, cmd) {
            return Ok(found);
        }
    }
    bail!("command not found: {cmd}")
}

/// Canonical path of the `node` the user's PATH selects.
pub fn active_node_executable() -> Result<PathBuf> {
    let node = find_command("node", &[], Path::new("."))
        .context("node is required to run JavaScript bins and was not found on PATH")?;
    std::fs::canonicalize(&node)
        .with_context(|| format!("failed to canonicalize Node executable {}", node.display()))
}

/// A parsed `#!` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shebang {
    pub interpreter: String,
    pub args: Vec<String>,
}

/// Parse the shebang of a script. `#!/usr/bin/env node` and
/// `#!/usr/bin/env -S node --flag` name the interpreter by command;
/// `#!/bin/sh` names it by path.
pub fn parse_shebang(first_line: &str) -> Option<Shebang> {
    let line = first_line.strip_prefix("#!")?.trim();
    if line.is_empty() {
        return None;
    }
    let mut parts = line.split_whitespace().map(String::from);
    let first = parts.next()?;
    let mut rest: Vec<String> = parts.collect();
    if first.ends_with("/env") || first == "env" {
        if rest.first().is_some_and(|flag| flag == "-S") {
            rest.remove(0);
        }
        if rest.is_empty() {
            return None;
        }
        let interpreter = rest.remove(0);
        return Some(Shebang {
            interpreter,
            args: rest,
        });
    }
    Some(Shebang {
        interpreter: first,
        args: rest,
    })
}

pub fn read_shebang(path: &Path) -> Option<Shebang> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let mut head = [0u8; 512];
    let read = file.read(&mut head).ok()?;
    let head = &head[..read];
    if !head.starts_with(b"#!") {
        return None;
    }
    let line_end = head.iter().position(|b| *b == b'\n').unwrap_or(head.len());
    let line = String::from_utf8_lossy(&head[..line_end]);
    parse_shebang(line.trim_end_matches('\r'))
}

/// The program and arguments to spawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    pub program: PathBuf,
    pub args: Vec<String>,
    /// Windows only: the complete command line to hand `cmd.exe` verbatim.
    /// `cmd /s /c` expects `"<script>"` as typed, not the per-argument MSVC
    /// quoting `std::process::Command` applies, which npm avoids the same
    /// way (`windowsVerbatimArguments`). When set, `args` is empty.
    pub raw_command_line: Option<String>,
}

/// Quote one token for a `cmd.exe` command line: tokens with whitespace are
/// wrapped in double quotes, everything else passes through.
fn cmd_token(token: &str) -> String {
    if token.is_empty() || token.chars().any(char::is_whitespace) {
        format!("\"{token}\"")
    } else {
        token.to_string()
    }
}

/// Decide how to execute `file` with `args`: via its shebang interpreter
/// (resolved on PATH, so `node` is the active Node), via `node` for
/// JavaScript without a shebang, via `cmd.exe` for Windows batch shims, or
/// directly for native executables.
pub fn plan_launch(file: &Path, args: &[String]) -> Result<Launch> {
    // The script sees the path it was invoked by, as it would under a shell:
    // bins such as cowsay/cowthink share one file and read their name from
    // `process.argv[1]`. The shebang and extension come from the real file.
    let invoked = if file.is_absolute() {
        file.to_path_buf()
    } else {
        std::env::current_dir()
            .context("failed to read the current directory")?
            .join(file)
    };
    let target = std::fs::canonicalize(file)
        .with_context(|| format!("resolving command {}", file.display()))?;
    let ext = target
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();
    if cfg!(windows) && matches!(ext.as_str(), "cmd" | "bat") {
        let comspec = std::env::var_os("ComSpec").unwrap_or_else(|| "cmd.exe".into());
        let line = std::iter::once(invoked.display().to_string())
            .chain(args.iter().cloned())
            .map(|token| cmd_token(&token))
            .collect::<Vec<_>>()
            .join(" ");
        return Ok(Launch {
            program: PathBuf::from(comspec),
            args: Vec::new(),
            raw_command_line: Some(format!("/d /s /c \"{line}\"")),
        });
    }
    if let Some(shebang) = read_shebang(&target) {
        let program = resolve_interpreter(&shebang.interpreter)?;
        let mut launch_args = shebang.args;
        launch_args.push(invoked.display().to_string());
        launch_args.extend(args.iter().cloned());
        return Ok(Launch {
            program,
            args: launch_args,
            raw_command_line: None,
        });
    }
    if matches!(ext.as_str(), "js" | "cjs" | "mjs") {
        let mut launch_args = vec![invoked.display().to_string()];
        launch_args.extend(args.iter().cloned());
        return Ok(Launch {
            program: active_node_executable()?,
            args: launch_args,
            raw_command_line: None,
        });
    }
    Ok(Launch {
        program: invoked,
        args: args.to_vec(),
        raw_command_line: None,
    })
}

/// An interpreter named by a shebang: an absolute path that exists is used
/// as is; anything else is looked up by basename on PATH, which keeps
/// `#!/usr/bin/node` working on systems where Node lives elsewhere.
fn resolve_interpreter(interpreter: &str) -> Result<PathBuf> {
    let path = Path::new(interpreter);
    if path.is_absolute() && path.is_file() {
        return std::fs::canonicalize(path).map_err(Into::into);
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(interpreter);
    let found = find_command(name, &[], Path::new("."))
        .with_context(|| format!("shebang interpreter {interpreter} was not found on PATH"))?;
    std::fs::canonicalize(&found).map_err(Into::into)
}

/// The shell `--call` scripts run under: npm's default `sh`, or `ComSpec`
/// on Windows.
pub fn shell_launch(script: &str) -> Launch {
    if cfg!(windows) {
        let comspec = std::env::var_os("ComSpec").unwrap_or_else(|| "cmd.exe".into());
        Launch {
            program: PathBuf::from(comspec),
            args: Vec::new(),
            raw_command_line: Some(format!("/d /s /c \"{script}\"")),
        }
    } else {
        Launch {
            program: PathBuf::from("sh"),
            args: vec!["-c".into(), script.to_string()],
            raw_command_line: None,
        }
    }
}

/// The environment npm's run-script gives an `npx` command: every
/// `node_modules/.bin` from `cwd` upward prepended to PATH after the explicit
/// bin directories, the lifecycle variables, and the `npm_package_*`
/// variables of the local project.
pub fn exec_env(
    cwd: &Path,
    prefix: &Path,
    bin_dirs: &[PathBuf],
    script: &str,
    node: Option<&Path>,
) -> Vec<(String, String)> {
    let mut path_entries: Vec<PathBuf> = bin_dirs.to_vec();
    for ancestor in cwd.ancestors() {
        path_entries.push(ancestor.join("node_modules").join(".bin"));
    }
    if let Some(existing) = std::env::var_os("PATH") {
        path_entries.extend(std::env::split_paths(&existing));
    }
    let mut seen = std::collections::HashSet::new();
    path_entries.retain(|entry| seen.insert(entry.clone()));
    let path = std::env::join_paths(path_entries)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| std::env::var("PATH").unwrap_or_default());

    let mut env = vec![
        ("PATH".to_string(), path),
        ("npm_lifecycle_event".to_string(), "npx".to_string()),
        ("npm_lifecycle_script".to_string(), script.to_string()),
        (
            "npm_package_json".to_string(),
            prefix.join("package.json").display().to_string(),
        ),
        ("INIT_CWD".to_string(), cwd.display().to_string()),
        (
            "npm_config_user_agent".to_string(),
            format!(
                "oath/{} node/{} {} {}",
                env!("CARGO_PKG_VERSION"),
                node_version().unwrap_or_else(|| "unknown".into()),
                std::env::consts::OS,
                std::env::consts::ARCH
            ),
        ),
    ];
    if let Some(node) = node {
        env.push(("npm_node_execpath".to_string(), node.display().to_string()));
    }
    if let Ok(text) = std::fs::read_to_string(prefix.join("package.json"))
        && let Ok(pkg) = serde_json::from_str::<serde_json::Value>(&text)
    {
        env.extend(crate::npm_package_env(&pkg));
    }
    env
}

fn node_version() -> Option<String> {
    let output = std::process::Command::new("node")
        .arg("--version")
        .output()
        .ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.trim_start_matches('v').to_string())
}

/// Spawn without a sandbox, inheriting stdio.
pub fn spawn_plain(
    launch: &Launch,
    cwd: &Path,
    env: &[(String, String)],
) -> Result<std::process::ExitStatus> {
    let mut command = std::process::Command::new(&launch.program);
    command.current_dir(cwd);
    #[cfg(windows)]
    if let Some(line) = &launch.raw_command_line {
        use std::os::windows::process::CommandExt;
        command.raw_arg(line);
    } else {
        command.args(&launch.args);
    }
    #[cfg(not(windows))]
    command.args(&launch.args);
    for (name, value) in env {
        command.env(name, value);
    }
    command
        .status()
        .with_context(|| format!("failed to execute {}", launch.program.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shebangs_parse_env_and_direct_interpreters() {
        assert_eq!(
            parse_shebang("#!/usr/bin/env node"),
            Some(Shebang {
                interpreter: "node".into(),
                args: vec![]
            })
        );
        assert_eq!(
            parse_shebang("#!/usr/bin/env -S node --no-warnings"),
            Some(Shebang {
                interpreter: "node".into(),
                args: vec!["--no-warnings".into()]
            })
        );
        assert_eq!(
            parse_shebang("#!/bin/sh -e"),
            Some(Shebang {
                interpreter: "/bin/sh".into(),
                args: vec!["-e".into()]
            })
        );
        assert_eq!(parse_shebang("#!"), None);
        assert_eq!(parse_shebang("console.log(1)"), None);
    }

    #[test]
    fn cmd_tokens_quote_only_whitespace() {
        assert_eq!(cmd_token("--version"), "--version");
        assert_eq!(cmd_token("hello world"), "\"hello world\"");
        assert_eq!(cmd_token(""), "\"\"");
    }

    #[test]
    fn local_prefix_walks_up_to_a_project() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        let nested = project.join("src").join("deep");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(project.join("package.json"), "{}").unwrap();
        assert_eq!(find_local_prefix(&nested), project);
        let lonely = dir.path().join("lonely");
        std::fs::create_dir_all(&lonely).unwrap();
        assert_eq!(find_local_prefix(&lonely), lonely);
    }

    #[test]
    fn bare_commands_cannot_contain_separators() {
        let dir = tempfile::tempdir().unwrap();
        assert!(find_command("../etc/passwd", &[], dir.path()).is_err());
        assert!(find_command("definitely-missing-command-xyz", &[], dir.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn walk_up_finds_bins_in_ancestors_and_plans_shebang_launches() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let bin_dir = dir.path().join("node_modules").join(".bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let script = bin_dir.join("hello");
        std::fs::write(&script, "#!/bin/sh\necho hi\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let nested = dir.path().join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();
        assert_eq!(walk_up_bin(&nested, "hello"), Some(bin_dir.clone()));
        assert_eq!(walk_up_bin(&nested, "nope"), None);
        let found = find_command("hello", std::slice::from_ref(&bin_dir), dir.path()).unwrap();
        let launch = plan_launch(&found, &["x".into()]).unwrap();
        assert_eq!(launch.program, std::fs::canonicalize("/bin/sh").unwrap());
        assert_eq!(launch.args.last().unwrap(), "x");
        assert_eq!(launch.args.len(), 2);
        // A bin invoked through a symlink keeps the invoked name in argv.
        let alias = bin_dir.join("hello-alias");
        std::os::unix::fs::symlink(&script, &alias).unwrap();
        let launch = plan_launch(&alias, &[]).unwrap();
        assert_eq!(launch.args, vec![alias.display().to_string()]);
    }

    #[test]
    fn exec_env_prepends_bin_dirs_and_sets_lifecycle_vars() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"demo","version":"1.0.0"}"#,
        )
        .unwrap();
        let bin = dir.path().join("cache").join("node_modules").join(".bin");
        let env = exec_env(
            dir.path(),
            dir.path(),
            std::slice::from_ref(&bin),
            "cowsay hi",
            None,
        );
        let lookup = |key: &str| env.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());
        assert!(
            lookup("PATH")
                .unwrap()
                .starts_with(&bin.display().to_string())
        );
        assert_eq!(lookup("npm_lifecycle_event").as_deref(), Some("npx"));
        assert_eq!(lookup("npm_lifecycle_script").as_deref(), Some("cowsay hi"));
        assert_eq!(lookup("npm_package_name").as_deref(), Some("demo"));
        assert!(
            lookup("npm_config_user_agent")
                .unwrap()
                .starts_with("oath/")
        );
    }
}
