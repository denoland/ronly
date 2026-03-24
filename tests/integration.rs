use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

const ROOTLESS_UID: u32 = 65_534;
const ROOTLESS_GID: u32 = 65_534;

struct RootlessIdentity {
    uid: u32,
    gid: u32,
    user: String,
}

fn ronly() -> Command {
    let bin = env!("CARGO_BIN_EXE_ronly");
    Command::new(bin)
}

fn ronly_from(bin: impl AsRef<Path>) -> Command {
    Command::new(bin.as_ref())
}

fn ronly_run(args: &[&str]) -> std::process::Output {
    ronly()
        .arg("--")
        .args(args)
        .output()
        .expect("failed to run ronly")
}

fn ronly_sh(cmd: &str) -> std::process::Output {
    ronly()
        .arg("--")
        .args(["bash", "-c", cmd])
        .output()
        .expect("failed to run ronly")
}

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

fn combined(out: &std::process::Output) -> String {
    format!("{}{}", stdout(out), stderr(out))
}

fn skip_if_not_linux() -> bool {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping: linux only");
        return true;
    }
    false
}

fn skip_if_not_root() -> bool {
    if skip_if_not_linux() {
        return true;
    }
    if !nix::unistd::geteuid().is_root() {
        eprintln!("skipping: not root");
        return true;
    }
    false
}

fn unique_path(base: &Path, prefix: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    base.join(format!("{}-{}-{}", prefix, std::process::id(), suffix))
}

fn unique_temp_path(prefix: &str) -> PathBuf {
    unique_path(&std::env::temp_dir(), prefix)
}

fn copy_executable(
    src: impl AsRef<Path>,
    prefix: &str,
) -> PathBuf {
    let copy = unique_temp_path(prefix);
    std::fs::copy(src.as_ref(), &copy).unwrap();
    let mut perms = std::fs::metadata(&copy).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&copy, perms).unwrap();
    copy
}

fn rootless_ronly_path() -> &'static Path {
    static ROOTLESS_RONLY: OnceLock<PathBuf> = OnceLock::new();
    ROOTLESS_RONLY
        .get_or_init(|| {
            copy_executable(
                env!("CARGO_BIN_EXE_ronly"),
                "ronly-rootless",
            )
        })
        .as_path()
}

fn rootless_identity() -> RootlessIdentity {
    if nix::unistd::geteuid().is_root() {
        let uid = std::env::var("SUDO_UID")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(ROOTLESS_UID);
        let gid = std::env::var("SUDO_GID")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(ROOTLESS_GID);
        let user = std::env::var("SUDO_USER")
            .unwrap_or_else(|_| "nobody".to_string());
        return RootlessIdentity { uid, gid, user };
    }

    RootlessIdentity {
        uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getegid() },
        user: std::env::var("USER")
            .unwrap_or_else(|_| "nobody".to_string()),
    }
}

fn ronly_rootless() -> Command {
    let mut cmd = ronly_from(rootless_ronly_path());
    let identity = rootless_identity();
    if nix::unistd::geteuid().is_root() {
        unsafe {
            cmd.pre_exec(move || {
                if libc::setgroups(0, std::ptr::null()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setgid(identity.gid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setuid(identity.uid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    cmd.env("HOME", "/tmp");
    cmd.env("USER", identity.user);
    cmd
}

fn ronly_rootless_from(bin: impl AsRef<Path>) -> Command {
    let mut cmd = ronly_from(bin);
    let identity = rootless_identity();
    if nix::unistd::geteuid().is_root() {
        unsafe {
            cmd.pre_exec(move || {
                if libc::setgroups(0, std::ptr::null()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setgid(identity.gid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setuid(identity.uid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    cmd.env("HOME", "/tmp");
    cmd.env("USER", identity.user);
    cmd
}

fn ronly_rootless_run(args: &[&str]) -> std::process::Output {
    ronly_rootless()
        .arg("--")
        .args(args)
        .output()
        .expect("failed to run rootless ronly")
}

fn ronly_rootless_sh(cmd: &str) -> std::process::Output {
    ronly_rootless()
        .arg("--")
        .args(["bash", "-c", cmd])
        .output()
        .expect("failed to run rootless ronly")
}

fn ronly_rootless_writable(
    dir: &Path,
    cmd: &str,
) -> std::process::Output {
    ronly_rootless()
        .arg("--writable")
        .arg(dir)
        .arg("--")
        .args(["bash", "-c", cmd])
        .output()
        .expect("failed to run rootless ronly")
}

fn skip_if_rootless_unavailable() -> bool {
    if skip_if_not_linux() {
        return true;
    }

    let out = ronly_rootless_run(&["true"]);
    if out.status.success() {
        return false;
    }

    let text = combined(&out);
    if text.contains("requires unprivileged user namespaces or root") {
        eprintln!(
            "skipping: unprivileged user namespaces unavailable"
        );
        return true;
    }
    if text.contains("uid/gid map: Permission denied") {
        eprintln!(
            "skipping: unprivileged uid/gid mapping unavailable"
        );
        return true;
    }

    panic!("rootless probe failed:\n{}", text);
}

// --- read operations ---

#[test]
fn echo_hello() {
    if skip_if_not_root() {
        return;
    }
    let out = ronly_run(&["echo", "hello"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("hello"));
}

#[test]
fn cat_etc_hostname() {
    if skip_if_not_root() {
        return;
    }
    let out = ronly_run(&["cat", "/etc/hostname"]);
    assert!(out.status.success());
    assert!(!stdout(&out).is_empty());
}

#[test]
fn ls_root() {
    if skip_if_not_root() {
        return;
    }
    let out = ronly_run(&["ls", "/"]);
    assert!(out.status.success());
}

#[test]
fn ps_aux() {
    if skip_if_not_root() {
        return;
    }
    let out = ronly_sh("ps aux | head -3");
    assert!(out.status.success());
}

// --- write operations blocked ---

#[test]
fn rm_blocked() {
    if skip_if_not_root() {
        return;
    }
    let out = ronly_sh("rm /etc/hostname 2>&1");
    assert!(!out.status.success());
    let text = combined(&out).to_lowercase();
    assert!(
        text.contains("read-only")
            || text.contains("not permitted")
    );
}

#[test]
fn touch_blocked() {
    if skip_if_not_root() {
        return;
    }
    let out = ronly_sh("touch /etc/ronly_test 2>&1");
    assert!(!out.status.success());
}

#[test]
fn mkdir_blocked() {
    if skip_if_not_root() {
        return;
    }
    let out = ronly_sh("mkdir /etc/ronly_test 2>&1");
    assert!(!out.status.success());
}

// --- writable mountpoints ---

#[test]
fn tmp_writable() {
    if skip_if_not_root() {
        return;
    }
    let out = ronly_sh(
        "echo test > /tmp/ronly_test && cat /tmp/ronly_test",
    );
    assert!(out.status.success());
    assert!(stdout(&out).contains("test"));
}

// --- rootless path ---

#[test]
fn rootless_tmp_subdir_writable() {
    if skip_if_rootless_unavailable() {
        return;
    }
    let dir = unique_temp_path("ronly-tmp");
    let cmd = format!("echo test > {0}/file && cat {0}/file", dir.display());
    let out = ronly_rootless_writable(&dir, &cmd);
    assert!(out.status.success(), "{}", combined(&out));
    assert!(stdout(&out).contains("test"));
}

#[test]
fn rootless_var_tmp_subdir_writable() {
    if skip_if_rootless_unavailable() {
        return;
    }
    let dir = unique_path(Path::new("/var/tmp"), "ronly-writable");
    let cmd = format!("echo test > {0}/file && cat {0}/file", dir.display());
    let out = ronly_rootless_writable(&dir, &cmd);
    assert!(out.status.success(), "{}", combined(&out));
    assert!(stdout(&out).contains("test"));
    std::fs::remove_dir_all(&dir).ok();
}

// --- rootless: reads work ---

#[test]
fn rootless_echo_hello() {
    if skip_if_rootless_unavailable() {
        return;
    }
    let out = ronly_rootless_run(&["echo", "hello"]);
    assert!(out.status.success(), "{}", combined(&out));
    assert!(stdout(&out).contains("hello"));
}

#[test]
fn rootless_cat_etc_hostname() {
    if skip_if_rootless_unavailable() {
        return;
    }
    let out = ronly_rootless_run(&["cat", "/etc/hostname"]);
    assert!(out.status.success(), "{}", combined(&out));
    assert!(!stdout(&out).is_empty());
}

#[test]
fn rootless_ls_root() {
    if skip_if_rootless_unavailable() {
        return;
    }
    let out = ronly_rootless_run(&["ls", "/"]);
    assert!(out.status.success(), "{}", combined(&out));
}

// --- rootless: writes blocked ---

#[test]
fn rootless_rm_blocked() {
    if skip_if_rootless_unavailable() {
        return;
    }
    let out = ronly_rootless_sh("rm /etc/hostname 2>&1");
    assert!(!out.status.success(), "{}", combined(&out));
    let text = combined(&out).to_lowercase();
    assert!(
        text.contains("read-only") || text.contains("not permitted"),
        "expected read-only or not permitted, got: {}",
        text
    );
}

#[test]
fn rootless_touch_blocked() {
    if skip_if_rootless_unavailable() {
        return;
    }
    let out = ronly_rootless_sh("touch /etc/ronly_test 2>&1");
    assert!(!out.status.success(), "{}", combined(&out));
}

#[test]
fn rootless_mkdir_blocked() {
    if skip_if_rootless_unavailable() {
        return;
    }
    let out = ronly_rootless_sh("mkdir /etc/ronly_test 2>&1");
    assert!(!out.status.success(), "{}", combined(&out));
}

// --- rootless: /tmp writable ---

#[test]
fn rootless_tmp_writable() {
    if skip_if_rootless_unavailable() {
        return;
    }
    let out = ronly_rootless_sh(
        "echo test > /tmp/ronly_test && cat /tmp/ronly_test",
    );
    assert!(out.status.success(), "{}", combined(&out));
    assert!(stdout(&out).contains("test"));
}

// --- rootless: seccomp ---

#[test]
fn rootless_kill_blocked() {
    if skip_if_rootless_unavailable() {
        return;
    }
    let out = ronly_rootless_sh("kill 1 2>&1");
    assert!(!out.status.success(), "{}", combined(&out));
    assert!(
        combined(&out).to_lowercase().contains("not permitted"),
        "expected 'not permitted', got: {}",
        combined(&out)
    );
}

// --- rootless: shims ---

#[test]
fn rootless_docker_exec_blocked() {
    if skip_if_rootless_unavailable() {
        return;
    }
    let out = ronly_rootless_sh("docker exec foo bar 2>&1");
    assert!(!out.status.success(), "{}", combined(&out));
    assert!(combined(&out).contains("blocked"), "{}", combined(&out));
}

#[test]
fn rootless_kubectl_delete_blocked() {
    if skip_if_rootless_unavailable() {
        return;
    }
    let out = ronly_rootless_sh("kubectl delete pod foo 2>&1");
    assert!(!out.status.success(), "{}", combined(&out));
    assert!(combined(&out).contains("blocked"), "{}", combined(&out));
}

// --- rootless: exit codes ---

#[test]
fn rootless_exit_0() {
    if skip_if_rootless_unavailable() {
        return;
    }
    let out = ronly_rootless_run(&["true"]);
    assert!(out.status.success(), "{}", combined(&out));
}

#[test]
fn rootless_exit_42() {
    if skip_if_rootless_unavailable() {
        return;
    }
    let out = ronly_rootless_sh("exit 42");
    assert_eq!(out.status.code(), Some(42), "{}", combined(&out));
}

// --- pid namespace ---

#[test]
fn ps_shows_host_init() {
    if skip_if_not_root() {
        return;
    }
    let out = ronly_run(&["ps", "-p", "1", "-o", "comm="]);
    assert!(out.status.success());
    let text = stdout(&out).to_lowercase();
    assert!(
        text.contains("init") || text.contains("systemd")
    );
}

#[test]
fn own_pid_is_1() {
    if skip_if_not_root() {
        return;
    }
    let out = ronly_sh("echo $$");
    assert!(out.status.success());
    assert_eq!(stdout(&out).trim(), "1");
}

// --- seccomp ---

#[test]
fn kill_blocked() {
    if skip_if_not_root() {
        return;
    }
    let out = ronly_sh("kill 1 2>&1");
    assert!(!out.status.success());
    assert!(combined(&out)
        .to_lowercase()
        .contains("not permitted"));
}

// --- shims ---

#[test]
fn docker_exec_blocked() {
    if skip_if_not_root() {
        return;
    }
    let out = ronly_sh("docker exec foo bar 2>&1");
    assert!(!out.status.success());
    assert!(combined(&out).contains("blocked"));
}

#[test]
fn docker_stop_blocked() {
    if skip_if_not_root() {
        return;
    }
    let out = ronly_sh("docker stop foo 2>&1");
    assert!(!out.status.success());
    assert!(combined(&out).contains("blocked"));
}

#[test]
fn kubectl_delete_blocked() {
    if skip_if_not_root() {
        return;
    }
    let out = ronly_sh("kubectl delete pod foo 2>&1");
    assert!(!out.status.success());
    assert!(combined(&out).contains("blocked"));
}

#[test]
fn kubectl_apply_blocked() {
    if skip_if_not_root() {
        return;
    }
    let out = ronly_sh("kubectl apply -f foo 2>&1");
    assert!(!out.status.success());
    assert!(combined(&out).contains("blocked"));
}

#[test]
fn rootless_shims_work_when_binary_runs_from_tmp() {
    if skip_if_rootless_unavailable() {
        return;
    }
    let copy =
        copy_executable(env!("CARGO_BIN_EXE_ronly"), "ronly-copy");

    let out = ronly_rootless_from(&copy)
        .arg("--")
        .args(["bash", "-c", "docker exec foo bar 2>&1"])
        .output()
        .expect("failed to run copied ronly");

    std::fs::remove_file(&copy).ok();

    assert!(!out.status.success(), "{}", combined(&out));
    assert!(combined(&out).contains("blocked"), "{}", combined(&out));
}

// --- exit codes ---

#[test]
fn exit_0() {
    if skip_if_not_root() {
        return;
    }
    let out = ronly_run(&["true"]);
    assert!(out.status.success());
}

#[test]
fn exit_1() {
    if skip_if_not_root() {
        return;
    }
    let out = ronly_run(&["false"]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn exit_42() {
    if skip_if_not_root() {
        return;
    }
    let out = ronly_sh("exit 42");
    assert_eq!(out.status.code(), Some(42));
}
