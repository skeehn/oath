//! Fail-closed macOS launcher using the kernel-enforced Seatbelt policy engine.
//!
//! Apple deprecates the `sandbox-exec` CLI, so availability is never inferred
//! from the binary alone. Oath runs an adversarial capability probe before it
//! advertises this backend and refuses native mode if any control fails.

use crate::{BackendCapabilities, NetworkMode, SandboxPlan};
use anyhow::{Context, Result, anyhow, ensure};
use std::collections::BTreeSet;
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant};

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

pub fn capabilities() -> BackendCapabilities {
    let available = std::path::Path::new(SANDBOX_EXEC).is_file();
    BackendCapabilities {
        backend: "macos-seatbelt-v1".into(),
        available,
        filesystem_isolation: available,
        network_isolation: available,
        process_isolation: available,
        resource_limits: available,
        degraded_reason: (!available).then(|| {
            "macOS Seatbelt launcher is unavailable; Oath will not silently downgrade".into()
        }),
    }
}

fn canonical_paths(paths: impl IntoIterator<Item = std::path::PathBuf>) -> Result<Vec<String>> {
    let mut canonical = BTreeSet::new();
    for path in paths {
        let path = std::fs::canonicalize(&path)
            .with_context(|| format!("sandbox path does not exist: {}", path.display()))?;
        let path = path
            .to_str()
            .with_context(|| format!("sandbox path is not valid UTF-8: {}", path.display()))?;
        canonical.insert(path.to_string());
    }
    Ok(canonical.into_iter().collect())
}

fn seatbelt_string(path: &str) -> Result<String> {
    ensure!(
        !path.chars().any(char::is_control),
        "sandbox paths containing control characters are unsupported"
    );
    Ok(path.replace('\\', "\\\\").replace('"', "\\\""))
}

fn profile(plan: &SandboxPlan) -> Result<String> {
    ensure!(
        plan.version == crate::SANDBOX_PLAN_VERSION,
        "unsupported sandbox plan version {}",
        plan.version
    );
    let read_only = canonical_paths(plan.read_only_paths.iter().cloned())?;
    let writable = canonical_paths(plan.writable_paths.iter().cloned())?;
    let mut lines = vec![
        "(version 1)".to_string(),
        // macOS userland needs broad access to platform services. Explicit deny
        // rules remove the package's dangerous capabilities, and narrower
        // allow rules restore only the captured plan paths.
        "(allow default)".to_string(),
        "(deny file-write*)".to_string(),
        "(deny file-read-data)".to_string(),
        "(deny process-exec)".to_string(),
        "(allow file-read-metadata)".to_string(),
        "(allow file-read-data (literal \"/\") (subpath \"/System\") (subpath \"/usr\") (subpath \"/bin\") (subpath \"/sbin\") (subpath \"/dev\") (subpath \"/private/var/db/dyld\") (subpath \"/opt/homebrew\") (subpath \"/usr/local\"))".to_string(),
        "(allow process-exec (subpath \"/System\") (subpath \"/usr\") (subpath \"/bin\") (subpath \"/sbin\") (subpath \"/opt/homebrew\") (subpath \"/usr/local\"))".to_string(),
        "(deny process-exec (literal \"/usr/bin/security\") (literal \"/usr/bin/osascript\") (literal \"/usr/bin/open\") (literal \"/usr/bin/pbcopy\") (literal \"/usr/bin/pbpaste\"))".to_string(),
        "(deny mach-lookup (global-name \"com.apple.securityd\") (global-name \"com.apple.security.agent\") (global-name \"com.apple.security.authhost\") (global-name \"com.apple.pboard\") (global-name \"com.apple.trustd.agent\"))".to_string(),
        "(allow file-write-data (literal \"/dev/null\") (literal \"/dev/tty\"))".to_string(),
    ];
    if plan.network == NetworkMode::Deny {
        lines.push("(deny network*)".to_string());
    } else {
        lines.push("(allow file-read-data (literal \"/private/etc/hosts\") (literal \"/private/etc/resolv.conf\") (literal \"/private/etc/localtime\") (subpath \"/private/etc/ssl\"))".to_string());
    }
    if !plan.allow_subprocesses {
        lines.push("(deny process-fork)".to_string());
    }

    let mut parents = BTreeSet::new();
    for path in read_only.iter().chain(&writable) {
        for parent in std::path::Path::new(path).ancestors().skip(1) {
            if parent != std::path::Path::new("/") {
                parents.insert(parent.to_path_buf());
            }
        }
    }
    for path in parents {
        let path = seatbelt_string(&path.display().to_string())?;
        lines.push(format!("(allow file-read-metadata (literal \"{path}\"))"));
        lines.push(format!("(allow file-read-data (literal \"{path}\"))"));
    }
    for path in read_only {
        let path = seatbelt_string(&path)?;
        lines.push(format!("(allow file-read-data (subpath \"{path}\"))"));
        lines.push(format!("(allow process-exec (subpath \"{path}\"))"));
    }
    for path in writable {
        let path = seatbelt_string(&path)?;
        lines.push(format!("(allow file-read-data (subpath \"{path}\"))"));
        lines.push(format!("(allow file-write* (subpath \"{path}\"))"));
        lines.push(format!("(allow process-exec (subpath \"{path}\"))"));
    }
    Ok(lines.join("\n") + "\n")
}

fn current_user_process_count() -> u64 {
    let uid = unsafe { libc::geteuid() }.to_string();
    Command::new("/bin/ps")
        .args(["-U", &uid, "-o", "pid="])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).lines().count() as u64)
        .unwrap_or(0)
}

unsafe fn apply_limits(plan: &SandboxPlan, existing_processes: u64) -> std::io::Result<()> {
    fn named(name: &str, result: std::io::Result<()>) -> std::io::Result<()> {
        result.map_err(|error| {
            std::io::Error::new(error.kind(), format!("{name} limit failed: {error}"))
        })
    }

    fn limit(resource: libc::c_int, value: u64) -> std::io::Result<()> {
        let mut rule: libc::rlimit = unsafe { std::mem::zeroed() };
        if unsafe { libc::getrlimit(resource, &mut rule) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        rule.rlim_cur = (value as libc::rlim_t).min(rule.rlim_max);
        if unsafe { libc::setrlimit(resource, &rule) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    named(
        "RLIMIT_NPROC",
        limit(
            libc::RLIMIT_NPROC,
            existing_processes.saturating_add(plan.limits.max_processes),
        ),
    )?;
    named(
        "RLIMIT_NOFILE",
        limit(libc::RLIMIT_NOFILE, plan.limits.max_open_files),
    )?;
    named(
        "RLIMIT_FSIZE",
        limit(libc::RLIMIT_FSIZE, plan.limits.max_file_bytes),
    )?;
    named(
        "RLIMIT_CPU",
        limit(libc::RLIMIT_CPU, plan.limits.timeout_secs.max(1)),
    )?;
    Ok(())
}

fn process_group_memory_bytes(process_group: i32, max_processes: u64) -> Result<u64> {
    const PROC_PGRP_ONLY: u32 = 2;
    let capacity = max_processes.clamp(1, 4096) as usize + 8;
    let mut pids = vec![0 as libc::pid_t; capacity];
    let bytes = unsafe {
        libc::proc_listpids(
            PROC_PGRP_ONLY,
            process_group as u32,
            pids.as_mut_ptr().cast(),
            std::mem::size_of_val(pids.as_slice()) as libc::c_int,
        )
    };
    ensure!(bytes >= 0, "failed to enumerate sandbox process group");
    let count = (bytes as usize / std::mem::size_of::<libc::pid_t>()).min(pids.len());
    let mut total = 0u64;
    for pid in pids.into_iter().take(count).filter(|pid| *pid > 0) {
        let mut usage: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::proc_pid_rusage(
                pid,
                libc::RUSAGE_INFO_V2,
                (&mut usage as *mut libc::rusage_info_v2).cast(),
            )
        };
        if result == 0 {
            total = total.saturating_add(usage.ri_phys_footprint);
        }
    }
    Ok(total)
}

pub fn run(plan: &SandboxPlan, program: &std::path::Path, args: &[String]) -> Result<ExitStatus> {
    run_with_env(plan, program, args, &[])
}

/// Like [`run`], but also sets `extra_env` for the sandboxed process. The
/// values are explicit, caller-computed variables (an exec's PATH and `npm_*`
/// environment), applied after the plan's host allowlist.
pub fn run_with_env(
    plan: &SandboxPlan,
    program: &std::path::Path,
    args: &[String],
    extra_env: &[(String, String)],
) -> Result<ExitStatus> {
    ensure!(
        std::path::Path::new(SANDBOX_EXEC).is_file(),
        "native macOS sandbox unavailable: {SANDBOX_EXEC} is missing; Oath will not silently fall back"
    );
    let profile = profile(plan)?;
    let existing_processes = current_user_process_count();
    let limits = plan.clone();
    let mut command = Command::new(SANDBOX_EXEC);
    command
        .arg("-p")
        .arg(profile)
        .arg(program)
        .args(args)
        .current_dir(&plan.workdir)
        .env_clear()
        .env("HOME", &plan.workdir)
        .env("TMPDIR", &plan.workdir);
    for name in &plan.environment_allowlist {
        if let Ok(value) = std::env::var(name) {
            command.env(name, value);
        }
    }
    for (name, value) in extra_env {
        command.env(name, value);
    }
    // SAFETY: pre_exec performs only libc process-group and rlimit operations.
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            apply_limits(&limits, existing_processes)
        });
    }

    let mut child = command
        .spawn()
        .with_context(|| format!("failed to launch macOS sandbox for {}", program.display()))?;
    let started = Instant::now();
    let process_group = child.id() as i32;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        let memory_bytes = process_group_memory_bytes(process_group, plan.limits.max_processes)?;
        if memory_bytes > plan.limits.max_memory_bytes {
            // SAFETY: the child created its own process group before exec.
            unsafe {
                libc::kill(-process_group, libc::SIGKILL);
            }
            let _ = child.wait();
            return Err(anyhow!(
                "sandboxed process group exceeded memory limit: {memory_bytes} > {} bytes",
                plan.limits.max_memory_bytes
            ));
        }
        if started.elapsed() > Duration::from_secs(plan.limits.timeout_secs.max(1)) {
            // SAFETY: the child created its own process group before exec; a
            // negative PID kills the complete sandboxed descendant tree.
            unsafe {
                libc::kill(-process_group, libc::SIGKILL);
            }
            let _ = child.wait();
            return Err(anyhow!(
                "sandboxed command timed out after {}s",
                plan.limits.timeout_secs
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Exercise every capability advertised by `capabilities` on the live kernel.
pub fn verify(root: &std::path::Path) -> Result<()> {
    let workdir = root.join("work");
    std::fs::create_dir_all(&workdir)?;
    let secret = root.join("outside-secret");
    let escape = root.join("outside-write");
    std::fs::write(&secret, "must-not-leak")?;
    // SAFETY: capability verification runs once and restores the variable.
    unsafe { std::env::set_var("OATH_MACOS_PROBE_SECRET", "must-not-leak") };
    let plan = SandboxPlan::strict("oath-capability-probe", workdir.clone());
    let script = "test -z \"$OATH_MACOS_PROBE_SECRET\" && printf inside > inside-write && test \"$(cat inside-write)\" = inside && ! cat \"$1\" >/dev/null 2>&1 && ! cat /etc/passwd >/dev/null 2>&1 && ! /usr/bin/security list-keychains >/dev/null 2>&1 && ! /usr/bin/sandbox-exec -p '(version 1) (allow default)' /bin/cat \"$1\" >/dev/null 2>&1 && ! { printf escape > \"$2\"; } 2>/dev/null && ! /bin/sh -c 'printf child > \"$1\"' oath-child \"$2\" 2>/dev/null";
    let status = run(
        &plan,
        std::path::Path::new("/bin/sh"),
        &[
            "-c".into(),
            script.into(),
            "oath-probe".into(),
            secret.display().to_string(),
            escape.display().to_string(),
        ],
    );
    unsafe { std::env::remove_var("OATH_MACOS_PROBE_SECRET") };
    ensure!(
        status?.success(),
        "filesystem, environment, or child probe failed"
    );
    ensure!(!escape.exists(), "sandbox child wrote outside its plan");

    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let network = run(
        &plan,
        std::path::Path::new("/usr/bin/nc"),
        &[
            "-G".into(),
            "1".into(),
            "-z".into(),
            "127.0.0.1".into(),
            port.to_string(),
        ],
    )?;
    ensure!(
        !network.success(),
        "sandbox unexpectedly opened a network connection"
    );
    ensure!(
        listener.accept().is_err(),
        "sandbox network probe reached the listener"
    );

    let mut no_children = plan.clone();
    no_children.allow_subprocesses = false;
    let child = run(
        &no_children,
        std::path::Path::new("/bin/sh"),
        &["-c".into(), "exec 2>/dev/null; /usr/bin/true & wait".into()],
    )?;
    ensure!(
        !child.success(),
        "sandbox unexpectedly created a child process"
    );

    let mut limited = plan;
    limited.limits.max_file_bytes = 1;
    let oversized = run(
        &limited,
        std::path::Path::new("/bin/sh"),
        &["-c".into(), "printf 1234 > oversized".into()],
    )?;
    ensure!(
        !oversized.success(),
        "sandbox file-size resource limit was not enforced"
    );

    let mut memory_limited = SandboxPlan::strict("memory-probe", workdir);
    memory_limited.limits.max_memory_bytes = 1;
    let memory = run(
        &memory_limited,
        std::path::Path::new("/bin/sh"),
        &["-c".into(), "sleep 2".into()],
    )
    .unwrap_err();
    ensure!(
        memory.to_string().contains("exceeded memory limit"),
        "sandbox memory resource limit was not enforced: {memory:#}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_escapes_paths_and_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let plan = SandboxPlan::strict("test", root.path().to_path_buf());
        let profile = profile(&plan).unwrap();
        assert!(profile.contains("(deny file-write*)"));
        assert!(profile.contains("(deny file-read-data)"));
        assert!(profile.contains("(deny process-exec)"));
        assert!(profile.contains("(deny network*)"));
        assert!(profile.contains(&root.path().display().to_string()));
        assert!(!profile.contains("(param"));
        assert_eq!(
            seatbelt_string("quote\"and\\slash").unwrap(),
            "quote\\\"and\\\\slash"
        );
    }

    #[test]
    fn live_adversarial_capability_probe_passes() {
        let root = tempfile::tempdir().unwrap();
        verify(root.path()).unwrap();
    }
}
