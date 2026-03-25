use std::process::Command;

fn ronly() -> Command {
    let bin = env!("CARGO_BIN_EXE_ronly");
    let mut cmd = Command::new(bin);
    // RONLY_TEST_MODE=privileged forces --privileged flag
    // so CI can test both paths
    if std::env::var("RONLY_TEST_MODE").as_deref() == Ok("privileged") {
        cmd.arg("--privileged");
    }
    cmd
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

fn combined(out: &std::process::Output) -> String {
    let s = String::from_utf8_lossy(&out.stdout);
    let e = String::from_utf8_lossy(&out.stderr);
    format!("{s}{e}")
}

// --- read operations ---

#[test]
fn echo_hello() {
    let out = ronly_run(&["echo", "hello"]);
    assert!(out.status.success(), "{}", combined(&out));
    assert!(stdout(&out).contains("hello"));
}

#[test]
fn cat_etc_hostname() {
    let out = ronly_run(&["cat", "/etc/hostname"]);
    assert!(out.status.success(), "{}", combined(&out));
    assert!(!stdout(&out).is_empty());
}

#[test]
fn ls_root() {
    let out = ronly_run(&["ls", "/"]);
    assert!(out.status.success(), "{}", combined(&out));
}

#[test]
fn ps_aux() {
    let out = ronly_sh("ps aux | head -3");
    assert!(out.status.success(), "{}", combined(&out));
}

// --- write operations blocked ---

#[test]
fn rm_blocked() {
    let out = ronly_sh("rm /etc/hostname 2>&1");
    assert!(!out.status.success());
    let text = combined(&out).to_lowercase();
    assert!(
        text.contains("read-only") || text.contains("not permitted"),
        "{}",
        text
    );
}

#[test]
fn touch_blocked() {
    let out = ronly_sh("touch /etc/ronly_test 2>&1");
    assert!(!out.status.success());
}

#[test]
fn mkdir_blocked() {
    let out = ronly_sh("mkdir /etc/ronly_test 2>&1");
    assert!(!out.status.success());
}

// --- /tmp writable ---

#[test]
fn tmp_writable() {
    let out = ronly_sh("echo test > /tmp/ronly_test && cat /tmp/ronly_test");
    assert!(out.status.success(), "{}", combined(&out));
    assert!(stdout(&out).contains("test"));
}

// --- /proc works (host processes visible) ---

#[test]
fn ps_works() {
    let out = ronly_sh("ps aux");
    assert!(out.status.success(), "{}", combined(&out));
}

// --- seccomp ---

#[test]
fn kill_blocked() {
    let out = ronly_sh("kill 1 2>&1");
    assert!(!out.status.success());
    assert!(combined(&out).to_lowercase().contains("not permitted"));
}

// --- shims ---

#[test]
fn docker_exec_blocked() {
    let out = ronly_sh("docker exec foo bar 2>&1");
    assert!(!out.status.success());
    assert!(combined(&out).contains("blocked"));
}

#[test]
fn docker_stop_blocked() {
    let out = ronly_sh("docker stop foo 2>&1");
    assert!(!out.status.success());
    assert!(combined(&out).contains("blocked"));
}

#[test]
fn kubectl_delete_blocked() {
    let out = ronly_sh("kubectl delete pod foo 2>&1");
    assert!(!out.status.success());
    assert!(combined(&out).contains("blocked"));
}

#[test]
fn kubectl_apply_blocked() {
    let out = ronly_sh("kubectl apply -f foo 2>&1");
    assert!(!out.status.success());
    assert!(combined(&out).contains("blocked"));
}

// --- no-network ---

#[test]
fn no_network_has_no_interfaces() {
    // An empty network namespace only has a loopback device,
    // and it starts DOWN. No eth0, no external connectivity.
    let out = ronly()
        .args(["--no-network", "--"])
        .args(["cat", "/proc/net/dev"])
        .output()
        .expect("failed to run ronly");
    assert!(out.status.success(), "{}", combined(&out));
    let text = stdout(&out);
    let interfaces: Vec<&str> = text
        .lines()
        .skip(2) // skip header lines
        .filter_map(|l| l.split(':').next())
        .map(|s| s.trim())
        .collect();
    assert_eq!(
        interfaces,
        vec!["lo"],
        "expected only loopback, got: {:?}",
        interfaces
    );
}

#[test]
fn no_network_local_ops_work() {
    let out = ronly()
        .args(["--no-network", "--"])
        .args([
            "bash",
            "-c",
            "ps aux > /tmp/diag && cat /proc/self/status >> /tmp/diag && wc -l /tmp/diag",
        ])
        .output()
        .expect("failed to run ronly");
    assert!(out.status.success(), "{}", combined(&out));
    assert!(!stdout(&out).is_empty());
}

// --- exit codes ---

#[test]
fn exit_0() {
    let out = ronly_run(&["true"]);
    assert!(out.status.success(), "{}", combined(&out));
}

#[test]
fn exit_1() {
    let out = ronly_run(&["false"]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn exit_42() {
    let out = ronly_sh("exit 42");
    assert_eq!(out.status.code(), Some(42));
}
