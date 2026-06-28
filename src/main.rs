use anyhow::Result;
use clap::Parser;
use std::io::IsTerminal;

mod sandbox;

#[derive(Parser, Debug)]
#[command(name = "ns-sandbox", version, about = "Cross-platform command-line ns-sandbox", long_about = None)]
struct Args {
    /// Assume "yes" for any confirmations
    #[arg(long)]
    yes: bool,

    /// Allow network access inside sandbox (may reduce isolation)
    #[arg(long)]
    allow_network: bool,

    /// Allow writes to system directories (may reduce isolation)
    #[arg(long)]
    allow_system_write: bool,

    /// Allow sandboxed writes to additional absolute paths
    #[arg(long, value_name = "PATH")]
    allow_write: Vec<String>,

    /// Kill sandboxed process after TIMEOUT seconds (0 = no limit)
    #[arg(long, value_name = "TIMEOUT", default_value_t = 0)]
    timeout: u64,

    /// Limit sandboxed process memory usage to MB (0 = no limit, macOS/Linux only)
    #[arg(long, value_name = "MB", default_value_t = 0)]
    memory_limit: u64,

    /// Mount filesystem as read-only (Linux: mount namespace, macOS: SBPL deny-write)
    #[arg(long)]
    read_only: bool,

    /// Limit maximum number of child processes (0 = no limit, Linux/macOS only)
    #[arg(long, value_name = "COUNT", default_value_t = 0)]
    process_limit: u32,

    /// Command to execute in sandbox (supports quoted arguments)
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.command.is_empty() {
        eprintln!("Error: No command specified");
        std::process::exit(1);
    }

    let command_str = args.command.join(" ");
    println!("Running in ns-sandbox: {}", command_str);

    let cwd = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("/"))
        .to_string_lossy()
        .to_string();

    let analysis = analyze_command(&command_str, &cwd);

    if !analysis.dangerous_reasons.is_empty() {
        let mut message = String::new();
        message.push_str("检测到可能的危险命令：\n");
        for r in &analysis.dangerous_reasons {
            message.push_str("  - ");
            message.push_str(r);
            message.push('\n');
        }
        message.push_str("仍然要继续执行吗？");

        let confirmed = if args.yes {
            true
        } else {
            confirm_interactive(&message)?
        };

        if !confirmed {
            eprintln!("已取消执行。");
            std::process::exit(2);
        }
    }

    let mut config = sandbox::SandboxConfig {
        allow_network: args.allow_network,
        allow_write_paths: args.allow_write,
        allow_system_write: args.allow_system_write,
        timeout_secs: args.timeout,
        memory_limit_mb: args.memory_limit,
        read_only: args.read_only,
        process_limit: args.process_limit,
    };

    if config.allow_system_write && analysis.needs_system_write {
        for p in &analysis.system_write_paths {
            if !config.allow_write_paths.iter().any(|x| x == p) {
                config.allow_write_paths.push(p.clone());
            }
        }
    }

    if analysis.needs_network && !config.allow_network {
        let confirmed = if args.yes {
            true
        } else {
            confirm_interactive("命令可能需要网络访问，是否允许网络？")?
        };
        if confirmed {
            config.allow_network = true;
        }
    }

    if !analysis.suggest_write_paths.is_empty() {
        let mut message = String::new();
        message.push_str("命令包含可能需要写入的路径（默认会被沙盒拒绝写入）：\n");
        for p in &analysis.suggest_write_paths {
            message.push_str("  - ");
            message.push_str(p);
            message.push('\n');
        }
        message.push_str("是否允许写入这些路径？");

        let confirmed = if args.yes {
            true
        } else {
            confirm_interactive(&message)?
        };
        if confirmed {
            for p in &analysis.suggest_write_paths {
                if !config.allow_write_paths.iter().any(|x| x == p) {
                    config.allow_write_paths.push(p.clone());
                }
            }
        }
    }

    if analysis.needs_system_write && !config.allow_system_write {
        let confirmed = if args.yes {
            true
        } else {
            confirm_interactive("命令可能需要写入系统目录（例如 /etc、/usr、/System），是否允许？")?
        };
        if confirmed {
            config.allow_system_write = true;
            for p in &analysis.system_write_paths {
                if !config.allow_write_paths.iter().any(|x| x == p) {
                    config.allow_write_paths.push(p.clone());
                }
            }
        }
    }

    sandbox::execute(&command_str, &config)?;

    Ok(())
}

#[derive(Debug, Default)]
struct CommandAnalysis {
    dangerous_reasons: Vec<String>,
    needs_network: bool,
    suggest_write_paths: Vec<String>,
    system_write_paths: Vec<String>,
    needs_system_write: bool,
}

fn analyze_command(command: &str, cwd: &str) -> CommandAnalysis {
    let mut analysis = CommandAnalysis::default();
    let lower = command.to_lowercase();

    if lower.starts_with("sudo ")
        || lower == "sudo"
        || lower.contains(" sudo ")
        || lower.contains("su ")
        || lower.contains(" doas ")
    {
        analysis
            .dangerous_reasons
            .push("包含提权执行（sudo/su/doas）".to_string());
    }

    if lower.starts_with("rm ")
        || lower.contains(" rm ")
        || lower.starts_with("rmdir ")
        || lower.contains(" rmdir ")
    {
        if lower.contains(" -rf") || lower.contains(" -fr") || lower.contains(" --no-preserve-root")
        {
            analysis
                .dangerous_reasons
                .push("包含递归删除（rm -rf / --no-preserve-root 等）".to_string());
        }
        if lower.contains(" /") || lower.contains(" /*") {
            analysis
                .dangerous_reasons
                .push("删除目标包含绝对路径（可能影响系统目录）".to_string());
        }
    }

    for kw in [
        "dd ",
        "mkfs",
        "fdisk",
        "diskutil ",
        "shutdown",
        "reboot",
        "halt",
        "kill -9 1",
    ] {
        if lower.contains(kw) {
            analysis
                .dangerous_reasons
                .push(format!("包含高风险关键字：{}", kw.trim()));
        }
    }

    let needs_network = lower.contains("http://")
        || lower.contains("https://")
        || lower.contains(" ssh ")
        || lower.starts_with("ssh ")
        || lower.contains(" scp ")
        || lower.starts_with("scp ")
        || lower.contains(" curl ")
        || lower.starts_with("curl ")
        || lower.contains(" wget ")
        || lower.starts_with("wget ")
        || lower.contains(" ping ")
        || lower.starts_with("ping ")
        || lower.contains(" npm ")
        || lower.starts_with("npm ")
        || lower.contains(" pnpm ")
        || lower.starts_with("pnpm ")
        || lower.contains(" yarn ")
        || lower.starts_with("yarn ")
        || lower.contains(" pip ")
        || lower.starts_with("pip ")
        || lower.contains(" brew ")
        || lower.starts_with("brew ")
        || lower.contains(" cargo ")
        || lower.starts_with("cargo ")
        || (lower.contains(" git ")
            || lower.starts_with("git ")
            || lower.contains("gh ")
            || lower.starts_with("gh "))
            && (lower.contains(" clone")
                || lower.contains(" fetch")
                || lower.contains(" pull")
                || lower.contains(" push")
                || lower.contains(" submodule")
                || lower.contains("://")
                || lower.contains("git@"));
    analysis.needs_network = needs_network;

    let allowed_write_roots = [
        normalize_root(cwd),
        "/tmp".to_string(),
        "/var/tmp".to_string(),
        "/private/tmp".to_string(),
        "/private/var/tmp".to_string(),
    ];
    let system_roots = [
        "/etc",
        "/usr",
        "/bin",
        "/sbin",
        "/System",
        "/Library",
        "/var/root",
    ];

    let mut candidates = Vec::<String>::new();
    if let Ok(parts) = shell_words::split(command) {
        for token in &parts {
            if token.starts_with('/') && token.len() > 1 {
                candidates.push(token.clone());
            }
        }
    }
    candidates.sort();
    candidates.dedup();

    for p in candidates {
        let p_norm = normalize_root(&p);
        if p_norm == "/" {
            continue;
        }
        if is_subpath(&p_norm, "/dev/null")
            || is_subpath(&p_norm, "/dev/zero")
            || is_subpath(&p_norm, "/dev/random")
            || is_subpath(&p_norm, "/dev/urandom")
            || is_subpath(&p_norm, "/dev/tty")
        {
            continue;
        }

        let in_allowed = allowed_write_roots.iter().any(|r| is_subpath(&p_norm, r));
        let is_system = system_roots.iter().any(|r| is_subpath(&p_norm, r));
        if is_system {
            analysis.needs_system_write = true;
            analysis.system_write_paths.push(p_norm.clone());
        } else if !in_allowed {
            analysis.suggest_write_paths.push(p_norm.clone());
        }
    }

    analysis
}

fn confirm_interactive(prompt: &str) -> Result<bool> {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        return Ok(false);
    }

    use std::io::Write;
    let mut stderr = std::io::stderr();
    writeln!(stderr, "{prompt} [y/N] ")?;
    stderr.flush()?;

    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let answer = line.trim().to_lowercase();
    Ok(answer == "y" || answer == "yes")
}

fn normalize_root(s: &str) -> String {
    let mut out = s.trim().to_string();
    while out.ends_with('/') && out.len() > 1 {
        out.pop();
    }
    out
}

fn is_subpath(path: &str, root: &str) -> bool {
    if path == root {
        return true;
    }
    let root_slash = format!("{}/", root.trim_end_matches('/'));
    path.starts_with(&root_slash)
}
