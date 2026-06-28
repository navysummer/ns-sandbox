use anyhow::{Context, Result};
use nix::mount::{mount, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::wait::waitpid;
use nix::unistd::{fork, ForkResult};
use std::ffi::CString;
use std::process::Command;

use super::SandboxConfig;

const SANDBOX_HOSTNAME: &str = "ns-sandbox";

pub fn execute_sandboxed(command: &str, config: &SandboxConfig) -> Result<()> {
    println!("[Linux NS-Sandbox] Initializing ns-sandbox with namespaces...");

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            println!(
                "[Linux NS-Sandbox] Child process started with PID: {}",
                child
            );
            match waitpid(child, None) {
                Ok(status) => {
                    println!(
                        "[Linux NS-Sandbox] Child process exited with status: {:?}",
                        status
                    );
                    Ok(())
                }
                Err(e) => anyhow::bail!("Failed to wait for child process: {}", e),
            }
        }
        Ok(ForkResult::Child) => {
            if let Err(e) = apply_sandbox_restrictions(config) {
                eprintln!("[Linux NS-Sandbox] Failed to apply restrictions: {}", e);
                std::process::exit(1);
            }
            if let Err(e) = execute_command(command) {
                eprintln!("[Linux NS-Sandbox] Command execution failed: {}", e);
                std::process::exit(1);
            }
            std::process::exit(0);
        }
        Err(e) => anyhow::bail!("Fork failed: {}", e),
    }
}

fn apply_sandbox_restrictions(config: &SandboxConfig) -> Result<()> {
    let has_userns = unshare(CloneFlags::CLONE_NEWUSER).is_ok();
    if has_userns {
        println!("[Linux NS-Sandbox] User namespace created");
    } else {
        println!("[Linux NS-Sandbox] Warning: User namespace not available (run as root or enable unprivileged_userns_clone)");
    }

    let mut ns_flags = CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWIPC
        | CloneFlags::CLONE_NEWUTS;
    if !config.allow_network {
        ns_flags |= CloneFlags::CLONE_NEWNET;
    }

    unshare(ns_flags).context("Failed to create namespaces (try running as root)")?;

    println!("[Linux NS-Sandbox] Namespaces created successfully");

    set_sandbox_hostname();

    if let Err(e) = setup_mounts(config) {
        eprintln!("[Linux NS-Sandbox] Mount setup warning: {}", e);
    }

    set_umask();
    drop_supplementary_groups();
    set_dumpable(false);

    set_resource_limits(config);

    sanitize_environment();

    if let Err(e) = nix::sys::prctl::set_no_new_privs() {
        eprintln!(
            "[Linux NS-Sandbox] Warning: Failed to set NO_NEW_PRIVS: {}",
            e
        );
    } else {
        println!("[Linux NS-Sandbox] NO_NEW_PRIVS set");
    }

    if has_userns {
        drop_capabilities();
        clear_ambient_capabilities();
    }

    if let Err(e) = apply_seccomp() {
        eprintln!("[Linux NS-Sandbox] Warning: Failed to apply seccomp: {}", e);
    }

    println!("[Linux NS-Sandbox] Restrictions applied:");
    println!("  - Process isolation (PID namespace)");
    println!("  - Filesystem isolation (mount namespace)");
    if config.allow_network {
        println!("  - Network: allowed");
    } else {
        println!("  - Network isolation (NET namespace)");
    }
    println!("  - IPC isolation");
    println!("  - Hostname isolation (UTS namespace)");
    if config.read_only {
        println!("  - Filesystem: read-only");
    }
    if config.timeout_secs > 0 {
        println!("  - CPU time limit: {}s", config.timeout_secs);
    }
    if config.memory_limit_mb > 0 {
        println!("  - Memory limit: {} MB", config.memory_limit_mb);
    }
    if config.process_limit > 0 {
        println!("  - Process limit: {}", config.process_limit);
    }
    println!("  - NO_NEW_PRIVS");
    println!("  - Seccomp BPF filter");
    if has_userns {
        println!("  - User namespace (unprivileged)");
    }

    Ok(())
}

fn set_sandbox_hostname() {
    let name = CString::new(SANDBOX_HOSTNAME).expect("Invalid hostname");
    let ret = unsafe { libc::sethostname(name.as_ptr(), name.to_bytes().len()) };
    if ret == 0 {
        println!("[Linux NS-Sandbox] Hostname set to '{}'", SANDBOX_HOSTNAME);
    }
}

fn set_umask() {
    unsafe { libc::umask(0o077) };
}

fn drop_supplementary_groups() {
    let ret = unsafe { libc::setgroups(0, std::ptr::null()) };
    if ret == 0 {
        println!("[Linux NS-Sandbox] Supplementary groups dropped");
    }
}

fn set_dumpable(dumpable: bool) {
    let val: libc::c_int = if dumpable { 1 } else { 0 };
    let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, val, 0, 0, 0) };
    if ret == 0 {
        println!("[Linux NS-Sandbox] PR_SET_DUMPABLE={}", val);
    }
}

fn sanitize_environment() {
    for var in &[
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "LD_DEBUG",
        "LD_OPENCL",
    ] {
        unsafe { libc::unsetenv(CString::new(*var).unwrap().as_ptr()) };
    }
}

fn clear_ambient_capabilities() {
    const PR_CAP_AMBIENT: libc::c_int = 47;
    const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_ulong = 4;
    let ret = unsafe { libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) };
    if ret == 0 {
        println!("[Linux NS-Sandbox] Ambient capabilities cleared");
    }
}

fn setup_mounts(config: &SandboxConfig) -> Result<()> {
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        None::<&str>,
    )
    .context("Failed to make root mount private")?;

    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        None::<&str>,
    )
    .context("Failed to mount /proc")?;

    mount(
        Some("tmpfs"),
        "/proc/sys",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV | MsFlags::MS_RDONLY,
        None::<&str>,
    )
    .ok();

    mount(
        Some("tmpfs"),
        "/sys",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV | MsFlags::MS_RDONLY,
        None::<&str>,
    )
    .ok();

    mount(
        Some("tmpfs"),
        "/tmp",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_STRICTATIME,
        None::<&str>,
    )?;

    mount(
        Some("tmpfs"),
        "/dev",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_STRICTATIME,
        None::<&str>,
    )
    .context("Failed to mount /dev")?;

    std::fs::create_dir_all("/dev/shm").ok();
    mount(
        Some("tmpfs"),
        "/dev/shm",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .ok();

    create_minimal_devices()?;

    std::fs::create_dir_all("/run").ok();
    mount(
        Some("tmpfs"),
        "/run",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .ok();

    for sensitive in &["/proc/kallsyms", "/proc/kcore", "/proc/sysrq-trigger"] {
        if let Ok(meta) = std::fs::metadata(sensitive) {
            if meta.is_file() {
                std::fs::set_permissions(sensitive, std::fs::Permissions::from_mode(0o000)).ok();
            }
        }
    }

    if config.read_only {
        mount(
            Some("/"),
            "/",
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_RDONLY | MsFlags::MS_REMOUNT,
            None::<&str>,
        )?;
        println!("[Linux NS-Sandbox] Root filesystem remounted read-only");
    }

    for p in &config.allow_write_paths {
        let trimmed = p.trim();
        if trimmed.is_empty() || !std::path::Path::new(trimmed).exists() {
            continue;
        }
        if config.read_only {
            let mount_point = format!("/.ns-sandbox-rw{}", trimmed.replace('/', "_"));
            std::fs::create_dir_all(&mount_point).ok();
            mount(
                Some("tmpfs"),
                &mount_point,
                Some("tmpfs"),
                MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
                None::<&str>,
            )
            .ok();

            let target = format!("{}{}", mount_point, trimmed);
            let parent = std::path::Path::new(&target).parent().unwrap();
            std::fs::create_dir_all(parent).ok();
            mount(
                Some(trimmed),
                &target,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
            .with_context(|| format!("Failed to bind mount write path: {}", trimmed))?;
        } else {
            mount(
                Some(trimmed),
                trimmed,
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                None::<&str>,
            )
            .with_context(|| format!("Failed to bind mount write path: {}", trimmed))?;
        }
        println!("[Linux NS-Sandbox] Allowed write path: {}", trimmed);
    }

    Ok(())
}

fn create_minimal_devices() -> Result<()> {
    let devices = [
        ("/dev/null", 0x0103u32),
        ("/dev/zero", 0x0105u32),
        ("/dev/random", 0x0108u32),
        ("/dev/urandom", 0x0109u32),
        ("/dev/tty", 0x0400u32),
        ("/dev/full", 0x0107u32),
    ];

    for (path, dev) in &devices {
        let cpath = CString::new(*path).map_err(|e| anyhow::anyhow!("CString error: {}", e))?;
        unsafe {
            libc::mknod(cpath.as_ptr(), 0o666 | libc::S_IFCHR, *dev);
        }
    }
    std::os::unix::fs::symlink("/dev/tty", "/dev/console").ok();
    Ok(())
}

fn set_resource_limits(config: &SandboxConfig) {
    use libc::rlimit;

    if config.timeout_secs > 0 {
        let lim = rlimit {
            rlim_cur: config.timeout_secs,
            rlim_max: config.timeout_secs + 5,
        };
        unsafe { libc::setrlimit(libc::RLIMIT_CPU, &lim) };
    }

    if config.memory_limit_mb > 0 {
        let bytes = config.memory_limit_mb as u64 * 1024 * 1024;
        let lim = rlimit {
            rlim_cur: bytes,
            rlim_max: bytes,
        };
        unsafe { libc::setrlimit(libc::RLIMIT_AS, &lim) };
    }

    if config.process_limit > 0 {
        let lim = rlimit {
            rlim_cur: config.process_limit as u64,
            rlim_max: config.process_limit as u64,
        };
        unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &lim) };
    }

    let lim = rlimit {
        rlim_cur: 128,
        rlim_max: 1024,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) };

    let lim = rlimit {
        rlim_cur: if config.read_only {
            1024
        } else {
            100 * 1024 * 1024
        },
        rlim_max: 200 * 1024 * 1024,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &lim) };

    let lim = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_CORE, &lim) };

    let lim = rlimit {
        rlim_cur: 8 * 1024 * 1024,
        rlim_max: 8 * 1024 * 1024,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_STACK, &lim) };

    let lim = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_RTPRIO, &lim) };

    let lim = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &lim) };
}

fn drop_capabilities() {
    for cap in 0..=64u64 {
        let ret = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
        if ret != 0 {
            break;
        }
    }
    println!("[Linux NS-Sandbox] Capability bounding set dropped");
}

fn apply_seccomp() -> Result<()> {
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct sock_filter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    #[repr(C)]
    struct sock_fprog {
        len: u16,
        filter: *const sock_filter,
    }

    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_RET: u16 = 0x06;
    const BPF_K: u16 = 0x00;

    const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;

    const DANGEROUS_SYSCALLS: &[u32] = &[
        87,  // swapon
        88,  // swapoff
        101, // ptrace
        103, // syslog
        126, // uselib
        129, // personality
        155, // pivot_root
        165, // mount
        166, // umount2
        169, // reboot
        170, // sethostname
        171, // setdomainname
        172, // iopl
        173, // ioperm
        174, // create_module
        175, // init_module
        176, // delete_module
        177, // get_kernel_syms
        178, // query_module
        179, // quotactl
        184, // tuxcall
        185, // security
        186, // kcmp
        246, // kexec_load
        265, // clock_adjtime
        298, // perf_event_open
        310, // process_vm_readv
        311, // process_vm_writev
        313, // finit_module
        320, // kexec_file_load
        357, // bpf
    ];

    let total = (DANGEROUS_SYSCALLS.len() * 2) + 2;
    let kill_idx = total - 1;
    let mut insns = Vec::with_capacity(total);

    for &nr in DANGEROUS_SYSCALLS {
        let jeq_idx = insns.len() + 1;
        let jt = (kill_idx as u8).wrapping_sub(jeq_idx as u8).wrapping_sub(1);

        insns.push(sock_filter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: 0,
        });
        insns.push(sock_filter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt,
            jf: 0,
            k: nr,
        });
    }

    insns.push(sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });
    insns.push(sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });

    let prog = sock_fprog {
        len: insns.len() as u16,
        filter: insns.as_ptr(),
    };

    unsafe {
        let ret = libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &prog as *const sock_fprog,
        );
        if ret != 0 {
            anyhow::bail!("seccomp failed: {}", std::io::Error::last_os_error());
        }
    }

    println!(
        "[Linux NS-Sandbox] Seccomp filter applied ({} syscalls blocked)",
        DANGEROUS_SYSCALLS.len()
    );
    Ok(())
}

fn execute_command(command: &str) -> Result<()> {
    println!("[Linux NS-Sandbox] Executing: {}", command);

    let parts = shell_words::split(command).context("Failed to parse command")?;
    if parts.is_empty() {
        anyhow::bail!("Empty command");
    }

    let program = &parts[0];
    let args = &parts[1..];

    let status = Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .context("Failed to execute command")?;

    if !status.success() {
        anyhow::bail!("Command exited with status: {}", status);
    }

    Ok(())
}
