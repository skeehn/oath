//! Fail-closed Linux launcher using bubblewrap's kernel namespace boundary.

use crate::{BackendCapabilities, NetworkMode, SandboxPlan};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, ExitStatus};

fn create_mount_parents(cmd: &mut Command, paths: impl IntoIterator<Item = std::path::PathBuf>) {
    let mut parents = std::collections::BTreeSet::new();
    for path in paths {
        for parent in path.ancestors().skip(1) {
            if parent == std::path::Path::new("/") {
                continue;
            }
            parents.insert(parent.to_path_buf());
        }
    }
    for parent in parents {
        if ["/usr", "/bin", "/lib", "/lib64", "/proc", "/dev"]
            .iter()
            .any(|system| parent == std::path::Path::new(system))
        {
            continue;
        }
        cmd.arg("--dir").arg(parent);
    }
}

fn bubblewrap() -> Option<&'static str> {
    ["bwrap", "/usr/bin/bwrap"]
        .into_iter()
        .find(|candidate| Command::new(candidate).arg("--version").output().is_ok())
}

fn current_user_process_count() -> u64 {
    // RLIMIT_NPROC is charged to the real UID, not the PID namespace. Account
    // for processes that already exist under a shared CI/service account so
    // the package receives exactly its declared additional allowance.
    let uid = unsafe { libc::geteuid() };
    std::fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .bytes()
                .all(|byte| byte.is_ascii_digit())
                && entry.metadata().is_ok_and(|metadata| metadata.uid() == uid)
        })
        .count() as u64
}

pub fn capabilities() -> BackendCapabilities {
    let available = bubblewrap().is_some();
    BackendCapabilities {
        backend: "linux-bwrap-landlock-seccomp-v3".into(),
        available,
        filesystem_isolation: available,
        network_isolation: available,
        process_isolation: available,
        resource_limits: available,
        degraded_reason: (!available).then(|| "bubblewrap is required for native mode".into()),
    }
}

pub fn run(
    plan: &SandboxPlan,
    program: &std::path::Path,
    args: &[String],
) -> anyhow::Result<ExitStatus> {
    run_with_env(plan, program, args, &[])
}

/// Like [`run`], but also sets `extra_env` inside the namespace. Extra
/// variables are explicit values the caller computed (for example the PATH
/// and `npm_*` variables of an exec), not names read from the host
/// environment, so the plan's allowlist still governs what leaks in.
pub fn run_with_env(
    plan: &SandboxPlan,
    program: &std::path::Path,
    args: &[String],
    extra_env: &[(String, String)],
) -> anyhow::Result<ExitStatus> {
    let bwrap = bubblewrap().ok_or_else(|| {
        anyhow::anyhow!(
            "native Linux sandbox unavailable: install bubblewrap; Oath will not silently fall back"
        )
    })?;
    let mut cmd = Command::new(bwrap);
    cmd.args([
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
    ]);
    if plan.network == NetworkMode::Deny {
        cmd.arg("--unshare-net");
    }
    create_mount_parents(
        &mut cmd,
        plan.read_only_paths
            .iter()
            .chain(&plan.writable_paths)
            .cloned(),
    );
    for path in ["/usr", "/bin", "/lib", "/lib64"] {
        if std::path::Path::new(path).exists() {
            cmd.args(["--ro-bind", path, path]);
        }
    }
    for path in &plan.read_only_paths {
        let p = path.to_string_lossy();
        cmd.args(["--ro-bind", p.as_ref(), p.as_ref()]);
    }
    for path in &plan.writable_paths {
        let p = path.to_string_lossy();
        cmd.args(["--bind", p.as_ref(), p.as_ref()]);
    }
    cmd.args(["--chdir", &plan.workdir.to_string_lossy(), "--clearenv"]);
    for name in &plan.environment_allowlist {
        if let Ok(value) = std::env::var(name) {
            cmd.args(["--setenv", name, &value]);
        }
    }
    for (name, value) in extra_env {
        cmd.args(["--setenv", name, value]);
    }
    let limits = plan.limits.clone();
    let nproc_limit = current_user_process_count().saturating_add(limits.max_processes);
    // SAFETY: pre_exec runs after fork and performs only async-signal-safe libc calls.
    unsafe {
        cmd.pre_exec(move || {
            fn limit(resource: libc::__rlimit_resource_t, value: u64) -> std::io::Result<()> {
                let value = value as libc::rlim_t;
                let rule = libc::rlimit {
                    rlim_cur: value,
                    rlim_max: value,
                };
                // SAFETY: `rule` points to an initialized rlimit value for this child process.
                if unsafe { libc::setrlimit(resource, &rule) } == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            limit(libc::RLIMIT_NPROC, nproc_limit)?;
            limit(libc::RLIMIT_NOFILE, limits.max_open_files)?;
            limit(libc::RLIMIT_FSIZE, limits.max_file_bytes)?;
            limit(libc::RLIMIT_AS, limits.max_memory_bytes)?;
            limit(libc::RLIMIT_CPU, limits.timeout_secs.max(1))?;
            Ok(())
        });
    }
    let executable = std::env::current_exe()?;
    let plan_file = tempfile::NamedTempFile::new()?;
    serde_json::to_writer(plan_file.as_file(), plan)?;
    let plan_path = plan_file.path().to_string_lossy().into_owned();
    cmd.args(["--dir", "/oath"]);
    cmd.arg("--ro-bind").arg(executable).arg("/oath/oath");
    cmd.args(["--ro-bind", &plan_path, "/oath/plan.json"]);
    cmd.arg("/oath/oath")
        .arg("__sandbox-launch")
        .arg("--plan")
        .arg("/oath/plan.json")
        .arg("--program")
        .arg(program)
        .arg("--")
        .args(args)
        .status()
        .map_err(Into::into)
}

/// Applies the in-namespace defense-in-depth controls and replaces the process.
/// This must only be called by Oath's hidden sandbox launcher command.
pub fn apply_inner(
    plan: &SandboxPlan,
    program: &std::path::Path,
    args: &[String],
) -> anyhow::Result<ExitStatus> {
    apply_landlock(plan)?;
    apply_seccomp(plan)?;
    let error = Command::new(program).args(args).exec();
    Ok(ExitStatus::from_raw(
        error.raw_os_error().unwrap_or(libc::EPERM) << 8,
    ))
}

fn apply_landlock(plan: &SandboxPlan) -> anyhow::Result<()> {
    use landlock::{
        ABI, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
        RulesetStatus, Scope,
    };
    // ABI V6 adds scoped abstract Unix sockets and signals. Requiring it keeps
    // IPC isolation fail-closed instead of silently accepting an older kernel.
    let abi = ABI::V6;
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .scope(Scope::from_all(abi))?
        .create()?;
    // A rule on a regular file (the Node binary granted by canonical path, a
    // bin script) may only carry file-applicable rights: directory rights
    // such as ReadDir on a file make the kernel reject the rule, which the
    // landlock crate reports as a partially enforced ruleset.
    for path in ["/usr", "/bin", "/lib", "/lib64"]
        .into_iter()
        .map(std::path::PathBuf::from)
        .chain(plan.read_only_paths.iter().cloned())
    {
        if path.exists() {
            let access = if path.is_dir() {
                AccessFs::from_read(abi)
            } else {
                AccessFs::from_read(abi) & AccessFs::from_file(abi)
            };
            ruleset = ruleset.add_rule(PathBeneath::new(PathFd::new(path)?, access))?;
        }
    }
    for path in &plan.writable_paths {
        if path.exists() {
            let access = if path.is_dir() {
                AccessFs::from_all(abi)
            } else {
                AccessFs::from_all(abi) & AccessFs::from_file(abi)
            };
            ruleset = ruleset.add_rule(PathBeneath::new(PathFd::new(path)?, access))?;
        }
    }
    let status = ruleset.restrict_self()?;
    anyhow::ensure!(
        status.ruleset == RulesetStatus::FullyEnforced,
        "Landlock is not fully enforced on this kernel"
    );
    Ok(())
}

fn apply_seccomp(plan: &SandboxPlan) -> anyhow::Result<()> {
    use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};
    let mut filter = ScmpFilterContext::new(ScmpAction::Errno(libc::EPERM))?;
    const ALLOWED: &[&str] = &[
        "read",
        "write",
        "readv",
        "writev",
        "pread64",
        "pwrite64",
        "close",
        "close_range",
        "fstat",
        "newfstatat",
        "statx",
        "lseek",
        "mmap",
        "mprotect",
        "munmap",
        "mremap",
        "madvise",
        "brk",
        "rt_sigaction",
        "rt_sigprocmask",
        "rt_sigreturn",
        "sigaltstack",
        "ioctl",
        "fcntl",
        "dup",
        "dup2",
        "dup3",
        "pipe",
        "pipe2",
        "poll",
        "ppoll",
        "select",
        "pselect6",
        "epoll_create1",
        "epoll_ctl",
        "epoll_wait",
        "epoll_pwait",
        "eventfd2",
        "timerfd_create",
        "timerfd_settime",
        "timerfd_gettime",
        "clock_gettime",
        "clock_nanosleep",
        "nanosleep",
        "gettimeofday",
        "getpid",
        "getppid",
        "gettid",
        "getuid",
        "geteuid",
        "getgid",
        "getegid",
        "getgroups",
        "uname",
        "sysinfo",
        "getrandom",
        "arch_prctl",
        "prctl",
        "getrlimit",
        "setrlimit",
        "getcpu",
        "restart_syscall",
        "membarrier",
        "openat",
        "openat2",
        "access",
        "faccessat2",
        "readlink",
        "readlinkat",
        "getcwd",
        "chdir",
        "fchdir",
        "getdents64",
        "mkdirat",
        // Legacy (non-*at) forms of the path syscalls above: libuv and glibc
        // still issue them on x86_64, and every one is covered by the same
        // Landlock rules as its *at equivalent, so allowing them adds no
        // capability.
        "mkdir",
        "rmdir",
        "unlink",
        "rename",
        "open",
        "creat",
        "stat",
        "lstat",
        "symlink",
        "link",
        "chmod",
        "fchmod",
        "fchmodat",
        "fchmodat2",
        "chown",
        "fchown",
        "fchownat",
        "lchown",
        "utimensat",
        "futimesat",
        "truncate",
        "flock",
        "fallocate",
        "fadvise64",
        "copy_file_range",
        "sendfile",
        "statfs",
        "fstatfs",
        "getdents",
        "umask",
        "msync",
        "mincore",
        "memfd_create",
        "inotify_init",
        "inotify_init1",
        "inotify_add_watch",
        "inotify_rm_watch",
        "epoll_pwait2",
        "clock_getres",
        "rt_sigtimedwait",
        "getrusage",
        "times",
        "getpgid",
        "getpgrp",
        "setpgid",
        "setsid",
        "unlinkat",
        "renameat2",
        "linkat",
        "symlinkat",
        "ftruncate",
        "fsync",
        "fdatasync",
        "execve",
        "execveat",
        "wait4",
        "waitid",
        "exit",
        "exit_group",
        "kill",
        "tgkill",
        "set_tid_address",
        "set_robust_list",
        "rseq",
        "futex",
        "sched_yield",
        "sched_getaffinity",
        "sched_getparam",
        "sched_getscheduler",
        "prlimit64",
    ];
    for name in ALLOWED {
        if let Ok(syscall) = ScmpSyscall::from_name(name) {
            filter.add_rule(ScmpAction::Allow, syscall)?;
        }
    }
    if plan.allow_subprocesses {
        for name in ["clone", "clone3", "fork", "vfork"] {
            if let Ok(syscall) = ScmpSyscall::from_name(name) {
                filter.add_rule(ScmpAction::Allow, syscall)?;
            }
        }
    }
    if plan.network == NetworkMode::Inherit {
        for name in [
            "socket",
            "socketpair",
            "connect",
            "bind",
            "listen",
            "accept",
            "accept4",
            "getsockname",
            "getpeername",
            "sendto",
            "recvfrom",
            "sendmsg",
            "recvmsg",
            "shutdown",
            "setsockopt",
            "getsockopt",
        ] {
            if let Ok(syscall) = ScmpSyscall::from_name(name) {
                filter.add_rule(ScmpAction::Allow, syscall)?;
            }
        }
    }
    filter.load()?;
    Ok(())
}
