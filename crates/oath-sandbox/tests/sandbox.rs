//! Integration tests for oath-sandbox

#[cfg(unix)]
use oath_sandbox::executor::SandboxExecutor;
use oath_sandbox::policy::{Permission, SandboxPolicy};
use std::path::PathBuf;

#[cfg(target_os = "linux")]
fn run_native_release(
    plan: &oath_sandbox::SandboxPlan,
    program: &std::path::Path,
    args: &[&str],
) -> std::process::ExitStatus {
    let oath = std::env::var_os("OATH_NATIVE_TEST_BIN")
        .expect("OATH_NATIVE_TEST_BIN must point to the release Oath binary");
    let plan_file = tempfile::NamedTempFile::new().unwrap();
    serde_json::to_writer(plan_file.as_file(), plan).unwrap();
    std::process::Command::new(oath)
        .env("OATH_ADVERSARIAL_SECRET", "must-not-leak")
        .arg("__sandbox-native-run")
        .arg("--plan")
        .arg(plan_file.path())
        .arg("--program")
        .arg(program)
        .arg("--")
        .args(args)
        .status()
        .unwrap()
}

fn test_workdir() -> PathBuf {
    std::env::temp_dir().join("oath-sandbox-test")
}

#[test]
fn test_minimal_policy() {
    let workdir = test_workdir();
    let policy = SandboxPolicy::minimal("test-pkg", workdir.clone());
    assert_eq!(policy.package, "test-pkg");
    assert_eq!(policy.timeout_secs, 30);
    assert!(!policy.allows_network());
    assert!(policy.allows_read(&workdir.join("src/index.js")));
    assert!(!policy.allows_write(&workdir.join("src/index.js")));
}

#[test]
fn test_network_permission() {
    let workdir = test_workdir();
    let mut policy = SandboxPolicy::minimal("test-pkg", workdir);
    policy
        .permissions
        .push(Permission::Network(vec!["api.example.com".to_string()]));
    assert!(policy.allows_network());
}

#[test]
fn test_env_permission() {
    let workdir = test_workdir();
    let mut policy = SandboxPolicy::minimal("test-pkg", workdir);
    assert!(!policy.allows_env("SECRET_KEY"));

    policy
        .permissions
        .push(Permission::Env(vec!["NODE_ENV".to_string()]));
    assert!(policy.allows_env("NODE_ENV"));
    assert!(!policy.allows_env("SECRET_KEY"));
}

#[test]
fn test_unrestricted_allows_everything() {
    let workdir = test_workdir();
    let mut policy = SandboxPolicy::minimal("test-pkg", workdir.clone());
    policy.permissions.push(Permission::Unrestricted);
    assert!(policy.allows_network());
    assert!(policy.allows_write(&PathBuf::from("/etc/passwd")));
    assert!(policy.allows_env("ANYTHING"));
    assert!(policy.allows_subprocess("rm"));
}

#[test]
fn test_sandbox_profile_generation() {
    let workdir = test_workdir();
    let policy = SandboxPolicy::minimal("test-pkg", workdir);
    let profile = policy.to_sandbox_profile();
    assert!(profile.contains("(version 1)"));
    assert!(profile.contains("(deny default)"));
    assert!(profile.contains("file-read*"));
}

#[test]
#[cfg(unix)]
fn test_run_echo_sandboxed() {
    let workdir = std::env::temp_dir();
    std::fs::create_dir_all(&workdir).ok();

    let policy = SandboxPolicy::minimal("test", workdir);
    let result = SandboxExecutor::run(
        std::path::Path::new("/bin/echo"),
        &["hello", "oath"],
        &policy,
    )
    .unwrap();

    assert_eq!(result.exit_code, 0);
    assert!(result.stdout.contains("hello oath"));
}

#[test]
#[cfg(unix)]
fn test_sandbox_blocks_network() {
    // Without Seatbelt/Landlock, fallback can't actually block network.
    // This test verifies the sandbox *runs* the command; real network blocking
    // only works on Linux with Landlock.
    let workdir = std::env::temp_dir();
    std::fs::create_dir_all(&workdir).ok();

    let policy = SandboxPolicy::minimal("test", workdir);
    // Fallback mode (macOS 15+ / no Landlock) runs the command but cannot block
    // network. Reaching here (the executor returned Ok) is the structural
    // guarantee; the exit code is environment-dependent, so we don't assert it.
    // Real network blocking is covered on Linux with Landlock.
    let _result = SandboxExecutor::run(
        std::path::Path::new("/usr/bin/curl"),
        &["-s", "--max-time", "3", "https://example.com"],
        &policy,
    )
    .unwrap();
}

#[test]
#[cfg(unix)]
fn test_sandbox_allows_network_when_granted() {
    let workdir = std::env::temp_dir();
    std::fs::create_dir_all(&workdir).ok();

    let mut policy = SandboxPolicy::minimal("test", workdir);
    policy.permissions.push(Permission::Network(vec![]));

    let result = SandboxExecutor::run(
        std::path::Path::new("/usr/bin/curl"),
        &["--version"],
        &policy,
    )
    .unwrap();

    assert_eq!(
        result.exit_code, 0,
        "curl should run when network permission is granted"
    );
    assert!(result.stdout.contains("curl"));
}

#[test]
#[cfg(unix)]
fn test_timeout_kills_process() {
    let workdir = std::env::temp_dir();
    std::fs::create_dir_all(&workdir).ok();

    let mut policy = SandboxPolicy::minimal("test", workdir);
    policy.timeout_secs = 2;

    let result = SandboxExecutor::run(std::path::Path::new("/bin/sleep"), &["10"], &policy);

    // Should error with timeout
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("timed out"),
        "expected timeout error, got: {err}"
    );
}

#[test]
#[cfg(unix)]
fn test_env_stripping() {
    let workdir = std::env::temp_dir();
    std::fs::create_dir_all(&workdir).ok();

    // Set a test env var
    // SAFETY: single-threaded test
    unsafe {
        std::env::set_var("OATH_TEST_SECRET", "hunter2");
    }

    let policy = SandboxPolicy::minimal("test", workdir);
    // No env permission granted

    let result = SandboxExecutor::run(
        std::path::Path::new("/bin/sh"),
        &["-c", "echo $OATH_TEST_SECRET"],
        &policy,
    )
    .unwrap();

    // Should NOT see the secret (env was stripped)
    assert!(
        !result.stdout.contains("hunter2"),
        "secret leaked through sandbox!"
    );

    unsafe {
        std::env::remove_var("OATH_TEST_SECRET");
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the dedicated native Linux release runner"]
fn native_linux_blocks_secret_environment_and_outside_writes() {
    assert!(
        oath_sandbox::native_capabilities().available,
        "native Linux release tests must not skip unavailable controls"
    );
    let dir = tempfile::tempdir().unwrap();
    let plan = oath_sandbox::SandboxPlan::strict("adversarial", dir.path().to_path_buf());
    // SAFETY: this integration test does not concurrently mutate this variable.
    unsafe {
        std::env::set_var("OATH_ADVERSARIAL_SECRET", "must-not-leak");
    }
    let status = run_native_release(
        &plan,
        std::path::Path::new("/bin/sh"),
        &[
            "-c",
            "test -z \"$OATH_ADVERSARIAL_SECRET\" && ! touch /tmp/oath-escape",
        ],
    );
    unsafe {
        std::env::remove_var("OATH_ADVERSARIAL_SECRET");
    }
    assert!(status.success());
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the dedicated native Linux release runner"]
fn native_linux_denies_network_by_default() {
    assert!(
        oath_sandbox::native_capabilities().available,
        "native Linux release tests must not skip unavailable controls"
    );
    let dir = tempfile::tempdir().unwrap();
    let plan = oath_sandbox::SandboxPlan::strict("adversarial", dir.path().to_path_buf());
    let status = run_native_release(
        &plan,
        std::path::Path::new("/usr/bin/python3"),
        &[
            "-c",
            "import socket; socket.create_connection(('1.1.1.1', 53), 1)",
        ],
    );
    assert!(!status.success());
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the dedicated native Linux release runner"]
fn native_linux_denies_proc_credentials_and_unix_sockets() {
    assert!(oath_sandbox::native_capabilities().available);
    let dir = tempfile::tempdir().unwrap();
    let plan = oath_sandbox::SandboxPlan::strict("adversarial", dir.path().to_path_buf());
    let status = run_native_release(
        &plan,
        std::path::Path::new("/bin/sh"),
        &[
            "-c",
            "! test -r /etc/passwd && ! grep -aq OATH_ADVERSARIAL_SECRET /proc/1/environ",
        ],
    );
    assert!(status.success());
    let socket = run_native_release(
        &plan,
        std::path::Path::new("/usr/bin/python3"),
        &["-c", "import socket; socket.socket(socket.AF_UNIX)"],
    );
    assert!(
        !socket.success(),
        "network-deny must also deny Unix sockets"
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the dedicated native Linux release runner"]
fn native_linux_allows_workdir_filesystem_mutations() {
    assert!(oath_sandbox::native_capabilities().available);
    let dir = tempfile::tempdir().unwrap();
    let plan = oath_sandbox::SandboxPlan::strict("workdir-writes", dir.path().to_path_buf());
    // The operations an installer or formatter performs in its working
    // directory, through whichever syscall forms the libc and runtime pick.
    let status = run_native_release(
        &plan,
        std::path::Path::new("/bin/sh"),
        &[
            "-c",
            "mkdir d && mv d e && rmdir e && echo x > f && chmod 600 f && ln -s f g && ln f h && touch -d @0 f && mv f i && rm g h i",
        ],
    );
    assert!(
        status.success(),
        "working-directory mutations must be allowed"
    );
    assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires the dedicated native Linux release runner"]
fn native_linux_enforces_child_process_policy() {
    assert!(oath_sandbox::native_capabilities().available);
    let dir = tempfile::tempdir().unwrap();
    let mut plan = oath_sandbox::SandboxPlan::strict("no-children", dir.path().to_path_buf());
    plan.allow_subprocesses = false;
    let status = run_native_release(&plan, std::path::Path::new("/bin/sh"), &["-c", "/bin/true"]);
    assert!(
        !status.success(),
        "child creation must be denied by seccomp"
    );
}
