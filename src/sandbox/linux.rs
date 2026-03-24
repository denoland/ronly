use nix::mount::MsFlags;
use nix::sched::CloneFlags;
use nix::unistd::ForkResult;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::path::Path;

use crate::shims;
use crate::Args;

fn die(msg: &str) -> ! {
    eprintln!("{}", msg);
    unsafe { libc::_exit(1) }
}

const ROOTLESS_SHIMS_DIR: &str = "/tmp/.ronly-shims";

fn mount_tmpfs(
    target: &str,
    size: &str,
) -> crate::Result<()> {
    let data = format!("size={}", size);
    nix::mount::mount(
        Some("tmpfs"),
        target,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(data.as_str()),
    )?;
    Ok(())
}

/// Set up mounts. Returns the shims dir actually used.
fn setup_mounts(
    args: &Args,
    self_exe: Option<&std::path::Path>,
    rootless: bool,
) -> crate::Result<String> {
    // Create dirs before going read-only
    if !rootless {
        std::fs::create_dir_all(shims::SHIMS_DIR).ok();
    }
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

    // Read-only root
    nix::mount::mount(
        Some("/"),
        "/",
        None::<&str>,
        MsFlags::MS_BIND
            | MsFlags::MS_REMOUNT
            | MsFlags::MS_RDONLY
            | MsFlags::MS_REC,
        None::<&str>,
    )?;

    let shims_dir;

    if rootless {
        mount_tmpfs("/tmp", &args.tmpfs_size)?;

        // Create writable subdirs inside the fresh /tmp
        for p in &args.writable {
            if p.starts_with("/tmp/")
                && p != Path::new(ROOTLESS_SHIMS_DIR)
            {
                std::fs::create_dir_all(p)?;
            }
        }

        // Copy shims into /tmp since we can't bind-mount
        // without privileges. Uses /proc/self/exe which
        // the kernel resolves to the open file regardless
        // of mount changes, unlike the pre-resolved path.
        shims_dir = ROOTLESS_SHIMS_DIR.to_string();
        std::fs::create_dir_all(&shims_dir)?;
        if self_exe.is_some() {
            shims::copy_shims(
                Path::new("/proc/self/exe"),
                &shims_dir,
            )?;
        }
    } else {
        // Privileged: mount shims BEFORE /tmp so the
        // binary (which may live under /tmp) is still
        // visible for bind-mounting.
        shims_dir = shims::SHIMS_DIR.to_string();
        mount_tmpfs(shims::SHIMS_DIR, "1m")?;
        if let Some(exe) = self_exe {
            shims::install_shims(exe, &shims_dir)?;
        }

        mount_tmpfs("/tmp", &args.tmpfs_size)?;
    }

    // Additional writable paths
    for p in &args.writable {
        let p = p.to_string_lossy();
        if rootless && p.as_ref() == ROOTLESS_SHIMS_DIR {
            continue;
        }
        mount_tmpfs(p.as_ref(), &args.tmpfs_size)?;
    }

    Ok(shims_dir)
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
    blocked.extend_from_slice(&[
        libc::SYS_unlink,
        libc::SYS_rmdir,
        libc::SYS_rename,
    ]);

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> =
        blocked
            .into_iter()
            .map(|sc| (sc, vec![]))
            .collect();

    // ptrace: block write ops, allow read ops
    #[allow(unused_mut)]
    let mut ptrace_write_ops: Vec<u64> = vec![
        libc::PTRACE_POKETEXT as u64,
        libc::PTRACE_POKEDATA as u64,
        libc::PTRACE_POKEUSER as u64,
        libc::PTRACE_SETREGSET as u64,
    ];
    #[cfg(target_arch = "x86_64")]
    ptrace_write_ops.extend_from_slice(&[
        libc::PTRACE_SETREGS as u64,
        libc::PTRACE_SETFPREGS as u64,
    ]);
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

    let arch =
        std::env::consts::ARCH.try_into().map_err(|e| {
            format!("unsupported arch: {}", e)
        })?;

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

fn setup_id_map(
    real_uid: u32,
    real_gid: u32,
) -> crate::Result<()> {
    use std::fs;
    // Must deny setgroups before writing gid_map as
    // unprivileged
    fs::write("/proc/self/setgroups", "deny")?;
    fs::write(
        "/proc/self/uid_map",
        format!("0 {} 1\n", real_uid),
    )?;
    fs::write(
        "/proc/self/gid_map",
        format!("0 {} 1\n", real_gid),
    )?;
    Ok(())
}

pub fn run(args: Args) -> crate::Result<()> {
    // Resolve the on-disk path before mounts change the FS
    let self_exe = if !args.no_shims {
        Some(std::fs::read_link("/proc/self/exe")?)
    } else {
        None
    };

    // Save real UID/GID before entering user namespace
    let real_uid: u32 = unsafe { libc::getuid() };
    let real_gid: u32 = unsafe { libc::getgid() };

    // Try rootless (user namespace) first, fall back to
    // privileged
    let used_userns = match nix::sched::unshare(
        CloneFlags::CLONE_NEWUSER
            | CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWPID,
    ) {
        Ok(()) => true,
        Err(_) => {
            if let Err(_) = nix::sched::unshare(
                CloneFlags::CLONE_NEWNS
                    | CloneFlags::CLONE_NEWPID,
            ) {
                eprintln!(
                    "ronly: requires unprivileged user \
                     namespaces or root"
                );
                std::process::exit(1);
            }
            false
        }
    };

    if used_userns {
        if let Err(e) =
            setup_id_map(real_uid, real_gid)
        {
            eprintln!("ronly: uid/gid map: {}", e);
            std::process::exit(1);
        }
    }

    match unsafe { nix::unistd::fork()? } {
        ForkResult::Parent { child } => {
            let status =
                nix::sys::wait::waitpid(child, None)?;
            let code = match status {
                nix::sys::wait::WaitStatus::Exited(
                    _, c,
                ) => c,
                _ => 1,
            };
            std::process::exit(code);
        }
        ForkResult::Child => {
            child_main(args, self_exe, used_userns);
        }
    }
}

fn child_main(
    args: Args,
    self_exe: Option<std::path::PathBuf>,
    rootless: bool,
) -> ! {
    let shims_dir = match setup_mounts(
        &args,
        self_exe.as_deref(),
        rootless,
    ) {
        Ok(d) => d,
        Err(e) => die(&format!("ronly: mounts: {}", e)),
    };

    if self_exe.is_some() {
        // PATH: extra shims > built-in shims > system
        let sys_path =
            std::env::var("PATH").unwrap_or_default();
        let mut parts: Vec<String> = args
            .extra_shims
            .iter()
            .map(|d| d.to_string_lossy().into_owned())
            .collect();
        parts.push(shims_dir);
        parts.push(sys_path);
        std::env::set_var("PATH", parts.join(":"));
    }

    if let Err(e) = setup_seccomp() {
        die(&format!("ronly: seccomp: {}", e));
    }

    // Default to $SHELL or /bin/bash
    let command = if args.command.is_empty() {
        vec![std::env::var("SHELL")
            .unwrap_or_else(|_| "/bin/bash".into())]
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
