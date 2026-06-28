# Changelog

## v0.0.2

- Linux: mount namespace, seccomp BPF, capabilities drop, NO_NEW_PRIVS, rlimits
- macOS: file-read restrictions, Mach IPC deny, IOKit deny, Apple Events deny
- Windows: config fix, memory/process/time limits via job object
- Cross-platform: `--timeout`, `--memory-limit`, `--read-only`, `--process-limit`
- Fix: proper command quoting via `shell_words`
- CI: GitHub Actions automated build & release pipeline
