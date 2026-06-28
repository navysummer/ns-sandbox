use anyhow::{Context, Result};
use std::process::Command;

use super::SandboxConfig;

pub fn execute_sandboxed(command: &str, config: &SandboxConfig) -> Result<()> {
    println!("[macOS NS-Sandbox] Initializing ns-sandbox...");

    if command.is_empty() {
        anyhow::bail!("Empty command");
    }

    sanitize_environment();

    let cwd = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("/"))
        .to_string_lossy()
        .to_string();

    let profile = build_sbpl_profile(config, &cwd);

    println!("[macOS NS-Sandbox] Restrictions applied:");
    println!("  - Process isolation");
    println!("  - File write restrictions");
    println!("  - File read restrictions");
    if config.allow_network {
        println!("  - Network: allowed (confirmed)");
    } else {
        println!("  - Network: denied");
    }
    if !config.allow_system_write {
        println!("  - System file writes: denied");
    }
    println!("  - Mach IPC: restricted");
    println!("  - Hardware access: restricted");
    println!("  - IOKit: restricted");
    if config.read_only {
        println!("  - File writes: globally denied");
    }
    if config.timeout_secs > 0 {
        println!("  - CPU time limit: {}s", config.timeout_secs);
    }
    if config.memory_limit_mb > 0 {
        println!("  - Memory limit: {} MB", config.memory_limit_mb);
    }
    println!("[macOS NS-Sandbox] Executing: {}", command);

    apply_resource_limits(config);

    let status = Command::new("sandbox-exec")
        .arg("-p")
        .arg(&profile)
        .arg("sh")
        .arg("-c")
        .arg(command)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status();

    match status {
        Ok(exit_status) => {
            if exit_status.success() {
                println!("[macOS NS-Sandbox] Command completed successfully");
                Ok(())
            } else {
                anyhow::bail!("Command exited with status: {}", exit_status);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!(
                "[macOS NS-Sandbox] Warning: sandbox-exec not available, using resource limits only"
            );
            fallback_execute(command, config)
        }
        Err(e) => {
            anyhow::bail!("Failed to execute command: {}", e);
        }
    }
}

fn build_sbpl_profile(config: &SandboxConfig, cwd: &str) -> String {
    let mut sb = String::new();
    sb.push_str("(version 1)\n");
    sb.push_str("(allow default)\n");

    if !config.allow_network {
        sb.push_str("(deny network*)\n");
    }

    sb.push_str("(deny syscall-unix (syscall-number 101))\n"); // ptrace
    sb.push_str("(deny syscall-unix (syscall-number 103))\n"); // syslog
    sb.push_str("(deny syscall-unix (syscall-number 126))\n"); // uselib
    sb.push_str("(deny syscall-unix (syscall-number 129))\n"); // personality
    sb.push_str("(deny syscall-unix (syscall-number 172))\n"); // iopl
    sb.push_str("(deny syscall-unix (syscall-number 173))\n"); // ioperm
    sb.push_str("(deny syscall-unix (syscall-number 174))\n"); // create_module
    sb.push_str("(deny syscall-unix (syscall-number 246))\n"); // kexec_load
    sb.push_str("(deny syscall-unix (syscall-number 298))\n"); // perf_event_open
    sb.push_str("(deny syscall-unix (syscall-number 357))\n"); // bpf

    if config.read_only {
        sb.push_str("(deny file-write*)\n");
    } else {
        sb.push_str("(deny file-write* (subpath \"/\"))\n");
        sb.push_str(&format!(
            "(allow file-write* (subpath \"{}\"))\n",
            escape_sbpl_string(cwd)
        ));
        sb.push_str("(allow file-write* (subpath \"/tmp\"))\n");
        sb.push_str("(allow file-write* (subpath \"/var/tmp\"))\n");
        sb.push_str("(allow file-write* (subpath \"/private/tmp\"))\n");
        sb.push_str("(allow file-write* (subpath \"/private/var/tmp\"))\n");
        sb.push_str(
            "(allow file-write* (regex #\"^/dev/(null|zero|random|urandom|tty|fd|stdin|stdout|stderr)$\"))\n",
        );
    }

    sb.push_str("(deny file-read* (subpath \"/etc/master.passwd\"))\n");
    sb.push_str("(deny file-read* (subpath \"/etc/shadow\"))\n");
    sb.push_str("(deny file-read* (subpath \"/var/db/dslocal\"))\n");
    sb.push_str("(deny file-read* (subpath \"/Users\"))\n");
    sb.push_str("(deny file-read* (subpath \"/root\"))\n");
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            sb.push_str(&format!(
                "(allow file-read* (subpath \"{}\"))\n",
                escape_sbpl_string(&home)
            ));
        }
    }

    sb.push_str("(allow process-exec)\n");
    sb.push_str("(allow process-fork)\n");

    if !config.allow_system_write {
        sb.push_str("(deny file-write* (subpath \"/etc\"))\n");
        sb.push_str("(deny file-write* (subpath \"/usr\"))\n");
        sb.push_str("(deny file-write* (subpath \"/bin\"))\n");
        sb.push_str("(deny file-write* (subpath \"/sbin\"))\n");
        sb.push_str("(deny file-write* (subpath \"/System\"))\n");
        sb.push_str("(deny file-write* (subpath \"/Library\"))\n");
        sb.push_str("(deny file-write* (subpath \"/var/root\"))\n");
    }

    sb.push_str("(deny mach-lookup)\n");
    sb.push_str("(deny appleevent-send)\n");
    sb.push_str("(deny iokit-open)\n");

    let mut extra_write_paths = std::collections::BTreeSet::<String>::new();
    for p in &config.allow_write_paths {
        let trimmed = p.trim();
        if trimmed.is_empty() {
            continue;
        }
        extra_write_paths.insert(trimmed.to_string());
    }
    for p in &extra_write_paths {
        sb.push_str(&format!(
            "(allow file-write* (subpath \"{}\"))\n",
            escape_sbpl_string(p)
        ));
    }

    sb
}

fn sanitize_environment() {
    for var in &[
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "DYLD_FALLBACK_FRAMEWORK_PATH",
        "DYLD_VERSIONED_LIBRARY_PATH",
        "DYLD_VERSIONED_FRAMEWORK_PATH",
        "DYLD_ROOT_PATH",
        "DYLD_SHARED_REGION",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
    ] {
        unsafe { libc::unsetenv(std::ffi::CString::new(*var).unwrap().as_ptr()) };
    }
}

fn fallback_execute(command: &str, config: &SandboxConfig) -> Result<()> {
    apply_resource_limits(config);

    let status = Command::new("sh")
        .arg("-c")
        .arg(command)
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

fn apply_resource_limits(config: &SandboxConfig) {
    use libc::{
        rlimit, RLIMIT_AS, RLIMIT_CORE, RLIMIT_CPU, RLIMIT_FSIZE, RLIMIT_NOFILE, RLIMIT_NPROC,
        RLIMIT_STACK,
    };

    if config.timeout_secs > 0 {
        let lim = rlimit {
            rlim_cur: config.timeout_secs,
            rlim_max: config.timeout_secs + 5,
        };
        unsafe { libc::setrlimit(RLIMIT_CPU, &lim) };
    }

    if config.memory_limit_mb > 0 {
        let bytes = config.memory_limit_mb * 1024 * 1024;
        let lim = rlimit {
            rlim_cur: bytes,
            rlim_max: bytes,
        };
        unsafe { libc::setrlimit(RLIMIT_AS, &lim) };
    }

    if config.process_limit > 0 {
        let lim = rlimit {
            rlim_cur: config.process_limit as u64,
            rlim_max: config.process_limit as u64,
        };
        unsafe { libc::setrlimit(RLIMIT_NPROC, &lim) };
    }

    let lim = rlimit {
        rlim_cur: 128,
        rlim_max: 1024,
    };
    unsafe { libc::setrlimit(RLIMIT_NOFILE, &lim) };

    let lim = rlimit {
        rlim_cur: 100 * 1024 * 1024,
        rlim_max: 200 * 1024 * 1024,
    };
    unsafe { libc::setrlimit(RLIMIT_FSIZE, &lim) };

    let lim = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe { libc::setrlimit(RLIMIT_CORE, &lim) };

    let lim = rlimit {
        rlim_cur: 8 * 1024 * 1024,
        rlim_max: 8 * 1024 * 1024,
    };
    unsafe { libc::setrlimit(RLIMIT_STACK, &lim) };
}

fn escape_sbpl_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\"', "\\\"")
        .replace(['\n', '\r'], "")
}
