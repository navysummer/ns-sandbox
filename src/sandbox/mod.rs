use anyhow::Result;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "windows")]
mod windows;

#[derive(Debug, Clone, Default)]
pub struct SandboxConfig {
    pub allow_network: bool,
    pub allow_write_paths: Vec<String>,
    pub allow_system_write: bool,
    pub timeout_secs: u64,
    pub memory_limit_mb: u64,
    pub read_only: bool,
    pub process_limit: u32,
}

pub fn execute(command: &str, config: &SandboxConfig) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::execute_sandboxed(command, config)
    }

    #[cfg(target_os = "macos")]
    {
        macos::execute_sandboxed(command, config)
    }

    #[cfg(target_os = "windows")]
    {
        windows::execute_sandboxed(command, config)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        anyhow::bail!("Unsupported platform")
    }
}
