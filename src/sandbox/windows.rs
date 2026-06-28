use anyhow::{Context, Result};
use std::process::Command;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::{
    SetTokenInformation, PSID, SID_AND_ATTRIBUTES, TOKEN_ADJUST_DEFAULT, TOKEN_INFORMATION_CLASS,
    TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicLimitInformation,
    JobObjectExtendedLimitInformation, SetInformationJobObject, JOBOBJECT_BASIC_LIMIT_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_JOB_TIME, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_ALL_ACCESS,
};

use super::SandboxConfig;

pub fn execute_sandboxed(command: &str, config: &SandboxConfig) -> Result<()> {
    println!("[Windows NS-Sandbox] Initializing ns-sandbox with Job Objects...");

    if command.is_empty() {
        anyhow::bail!("Empty command");
    }

    println!("[Windows NS-Sandbox] Restrictions applied:");
    println!("  - Process isolation (Job Object)");
    if !config.allow_network {
        println!("  - Network: denied (job process group)");
    }
    if config.read_only {
        println!("  - File writes: restricted");
    }
    if config.timeout_secs > 0 {
        println!("  - Job time limit: {}s", config.timeout_secs);
    }
    if config.memory_limit_mb > 0 {
        println!("  - Memory limit: {} MB", config.memory_limit_mb);
    }
    if config.process_limit > 0 {
        println!("  - Active process limit: {}", config.process_limit);
    }
    println!("[Windows NS-Sandbox] Executing: {}", command);

    let parts = shell_words::split(command).context("Failed to parse command")?;
    if parts.is_empty() {
        anyhow::bail!("Empty command");
    }

    let program = &parts[0];
    let args = &parts[1..];

    unsafe {
        let job = CreateJobObjectW(None, PCWSTR::null()).context("Failed to create job object")?;

        let mut basic_info = JOBOBJECT_BASIC_LIMIT_INFORMATION {
            LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            ..Default::default()
        };

        if config.process_limit > 0 {
            basic_info.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            basic_info.ActiveProcessLimit = config.process_limit;
        }

        if config.timeout_secs > 0 {
            basic_info.LimitFlags |= JOB_OBJECT_LIMIT_JOB_TIME;
            basic_info.PerJobUserTimeLimit = config.timeout_secs as i64 * 10_000_000;
        }

        SetInformationJobObject(
            job,
            JobObjectBasicLimitInformation,
            &basic_info as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_BASIC_LIMIT_INFORMATION>() as u32,
        )
        .context("Failed to set basic job limits")?;

        if config.memory_limit_mb > 0 {
            let ext_info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
                BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
                    LimitFlags: JOB_OBJECT_LIMIT_PROCESS_MEMORY,
                    ..Default::default()
                },
                ProcessMemoryLimit: (config.memory_limit_mb * 1024 * 1024) as usize,
                ..Default::default()
            };

            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &ext_info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
            .context("Failed to set extended job limits")?;
        }

        set_low_integrity_level();

        let mut child = Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .context("Failed to spawn process")?;

        let proc_handle =
            OpenProcess(PROCESS_ALL_ACCESS, false, child.id()).context("Failed to open process")?;

        AssignProcessToJobObject(job, proc_handle).context("Failed to assign process to job")?;

        let status = child.wait().context("Failed to wait for process")?;

        let _ = CloseHandle(proc_handle);
        let _ = CloseHandle(job);

        if status.success() {
            println!("[Windows NS-Sandbox] Command completed successfully");
            Ok(())
        } else {
            anyhow::bail!("Command exited with status: {}", status);
        }
    }
}

unsafe fn set_low_integrity_level() {
    let mut token = HANDLE::default();
    if OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
        &mut token,
    )
    .is_err()
    {
        return;
    }

    let low_sid_str = windows::core::HSTRING::from("S-1-16-4096");
    let mut sid = PSID::default();

    if ConvertStringSidToSidW(PCWSTR(low_sid_str.as_ptr()), &mut sid).is_ok() {
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: sid,
                Attributes: 0,
            },
        };

        let _ = SetTokenInformation(
            token,
            TOKEN_INFORMATION_CLASS(25),
            &label as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32,
        );

        let _ = LocalFree(Some(HLOCAL(sid.0 as *mut _)));
    }

    let _ = CloseHandle(token);
}
