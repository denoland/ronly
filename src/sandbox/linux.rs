use nix::mount::MsFlags;
use nix::sched::CloneFlags;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::path::Path;

use crate::shims;
use crate::Args;

fn die(msg: &str) -> ! {
    eprintln!("{}", msg);
    unsafe { libc::_exit(1) }
}

const SHIMS_DIR: &str = "/tmp/.ronly-shims";

fn mount_tmpfs(target: &str, size: &str) -> crate::Result<()> {
    nix::mount::mount(
        Some("tmpfs"),
        target,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(format!("size={}", size).as_str()),
    )?;
    Ok(())
}

fn setup_mounts(args: &Args, has_shims: bool) -> crate::Result<()> {
    // Create writable mount points before going read-only.
    // Silently fails in rootless mode (no real root).
    for p in &args.writable {
        std::fs::create_dir_all(p).ok();
    }

    // Private mount tree
    nix::mount::mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )?;

    // Read-only root (non-recursive so /proc stays
    // functional — seccomp blocks writes anyway)
    nix::mount::mount(
        Some("/"),
        "/",
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
        None::<&str>,
    )?;

    // Writable /tmp
    mount_tmpfs("/tmp", &args.tmpfs_size)?;

    // Copy shims into /tmp. /proc/self/exe resolves
    // through the kernel's open-file reference, so it
    // works even after mounts change.
    if has_shims {
        shims::copy_shims(Path::new("/proc/self/exe"), SHIMS_DIR)?;
    }

    // Additional writable paths
    for p in &args.writable {
        mount_tmpfs(&p.to_string_lossy(), &args.tmpfs_size)?;
    }

    Ok(())
}

fn setup_seccomp() -> crate::Result<()> {
    use seccompiler::SeccompAction;
    use seccompiler::SeccompCmpArgLen;
    use seccompiler::SeccompCmpOp;
    use seccompiler::SeccompCondition;
    use seccompiler::SeccompFilter;
    use seccompiler::SeccompRule;

    #[allow(unused_mut)]
    let mut blocked: Vec<i64> = vec![
        libc::SYS_kill,
        libc::SYS_tkill,
        libc::SYS_tgkill,
        libc::SYS_unlinkat,
        libc::SYS_renameat,
        libc::SYS_renameat2,
        libc::SYS_truncate,
        libc::SYS_ftruncate,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_reboot,
    ];
    #[cfg(target_arch = "x86_64")]
    blocked.extend_from_slice(&[libc::SYS_unlink, libc::SYS_rmdir, libc::SYS_rename]);

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> =
        blocked.into_iter().map(|sc| (sc, vec![])).collect();

    // ptrace: block write ops, allow read ops
    #[allow(unused_mut)]
    let mut ptrace_write_ops: Vec<u64> = vec![
        libc::PTRACE_POKETEXT as u64,
        libc::PTRACE_POKEDATA as u64,
        libc::PTRACE_POKEUSER as u64,
        libc::PTRACE_SETREGSET as u64,
    ];
    #[cfg(target_arch = "x86_64")]
    ptrace_write_ops
        .extend_from_slice(&[libc::PTRACE_SETREGS as u64, libc::PTRACE_SETFPREGS as u64]);
    let ptrace_rules: Vec<SeccompRule> = ptrace_write_ops
        .into_iter()
        .map(|op| {
            SeccompRule::new(vec![SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                op,
            )
            .unwrap()])
            .unwrap()
        })
        .collect();
    rules.insert(libc::SYS_ptrace, ptrace_rules);

    let arch = std::env::consts::ARCH
        .try_into()
        .map_err(|e| format!("unsupported arch: {}", e))?;

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )?;

    let bpf: seccompiler::BpfProgram = filter.try_into()?;
    seccompiler::apply_filter(&bpf)?;
    Ok(())
}

pub fn run(args: Args) -> crate::Result<()> {
    use crate::Mode;

    let has_shims = !args.no_shims;
    let real_uid = unsafe { libc::getuid() };
    let real_gid = unsafe { libc::getgid() };

    let net_flag = if args.no_network {
        CloneFlags::CLONE_NEWNET
    } else {
        CloneFlags::empty()
    };

    let rootless = match args.mode {
        Mode::Rootless => {
            if let Err(_) =
                nix::sched::unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS | net_flag)
            {
                eprintln!(
                    "ronly: user namespaces unavailable, \
                     try --privileged as root"
                );
                std::process::exit(1);
            }
            true
        }
        Mode::Privileged => {
            if let Err(_) = nix::sched::unshare(CloneFlags::CLONE_NEWNS | net_flag) {
                eprintln!(
                    "ronly: --privileged requires root \
                     (CAP_SYS_ADMIN), try --rootless"
                );
                std::process::exit(1);
            }
            false
        }
        Mode::Auto => {
            match nix::sched::unshare(
                CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS | net_flag,
            ) {
                Ok(()) => true,
                Err(_) => {
                    if let Err(_) = nix::sched::unshare(CloneFlags::CLONE_NEWNS | net_flag) {
                        eprintln!(
                            "ronly: needs user namespaces \
                             or root, see --rootless \
                             and --privileged"
                        );
                        std::process::exit(1);
                    }
                    false
                }
            }
        }
    };

    if rootless {
        eprintln!("ronly: using user namespaces (--rootless)");
        let map_ok = std::fs::write("/proc/self/setgroups", "deny")
            .and_then(|_| std::fs::write("/proc/self/uid_map", format!("0 {} 1\n", real_uid)))
            .and_then(|_| std::fs::write("/proc/self/gid_map", format!("0 {} 1\n", real_gid)));
        if let Err(e) = map_ok {
            eprintln!("ronly: uid/gid mapping failed: {e}");
            std::process::exit(1);
        }
    } else {
        eprintln!("ronly: using root privileges (--privileged)");
    }

    if args.no_network {
        eprintln!("ronly: network disabled (--no-network)");
    }

    if let Err(e) = setup_mounts(&args, has_shims) {
        die(&format!("ronly: mounts: {}", e));
    }

    if has_shims {
        let sys_path = std::env::var("PATH").unwrap_or_default();
        let mut parts: Vec<String> = args
            .extra_shims
            .iter()
            .map(|d| d.to_string_lossy().into_owned())
            .collect();
        parts.push(SHIMS_DIR.to_string());
        parts.push(sys_path);
        std::env::set_var("PATH", parts.join(":"));
    }

    if let Err(e) = setup_seccomp() {
        die(&format!("ronly: seccomp: {}", e));
    }

    // Default to $SHELL or /bin/bash
    let command = if args.command.is_empty() {
        vec![std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".into())]
    } else {
        args.command
    };
    let argv: Vec<CString> = command
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap())
        .collect();
    let argv_refs: Vec<&CString> = argv.iter().collect();
    nix::unistd::execvp(&argv[0], &argv_refs).unwrap();
    unreachable!()
}
