# ns-sandbox

跨平台命令行沙盒工具，支持 Linux、macOS 和 Windows。

## 功能特性

- **跨平台**: Linux (namespaces + seccomp)、macOS (sandbox-exec)、Windows (Job Objects)
- **文件系统隔离**: 写保护、读保护、只读模式 (`--read-only`)
- **网络隔离**: 按需允许网络访问 (`--allow-network` / `--allow-n`)
- **资源限制**: CPU 时间、内存、进程数 (`--timeout` / `--memory-limit` / `--process-limit`)
- **系统调用过滤**: Linux seccomp BPF 阻止危险系统调用
- **能力丢弃**: Linux capability bounding set 清空 + NO_NEW_PRIVS
- **IPC 限制**: macOS Mach IPC / Apple Events / IOKit 拒绝
- **危险命令检测**: 内置分析器检测 sudo、rm -rf、dd、mkfs 等高危操作
- **智能交互**: 自动检测命令是否需要网络/写路径，交互式确认
- **CI/CD 流水线**: GitHub Actions 自动构建并发布到 GitHub Releases

## 安装

```bash
# 从源码编译（当前平台）
cargo build --release
# 二进制位于 target/release/ns-sandbox

# 或从 GitHub Releases 下载预编译包

# Linux 发行版包：
# Debian/Ubuntu
sudo dpkg -i ns-sandbox_<version>_amd64.deb    # x86_64
sudo dpkg -i ns-sandbox_<version>_arm64.deb    # ARM64

# Fedora/RHEL/CentOS
sudo rpm -ivh ns-sandbox-<version>-1.x86_64.rpm    # x86_64
sudo rpm -ivh ns-sandbox-<version>-1.aarch64.rpm   # ARM64

# Alpine
sudo apk add --allow-untrusted ns-sandbox-<version>-r1.apk    # x86_64 或 ARM64
```

### 交叉编译

```bash
# Linux x86_64 (glibc)
cargo build --release --target x86_64-unknown-linux-gnu

# Linux x86_64 (musl, 静态链接，兼容所有发行版)
cargo build --release --target x86_64-unknown-linux-musl

# Linux i686 (32位)
cargo build --release --target i686-unknown-linux-gnu

# Linux ARM64 (glibc)
cargo build --release --target aarch64-unknown-linux-gnu

# Linux ARM64 (musl, 静态链接)
cargo build --release --target aarch64-unknown-linux-musl

# macOS x86_64
cargo build --release --target x86_64-apple-darwin

# macOS ARM64 (Apple Silicon)
cargo build --release --target aarch64-apple-darwin

# Windows x86_64
cargo build --release --target x86_64-pc-windows-msvc
```

> 交叉编译需要安装对应目标平台的工具链：`rustup target add <target>`。Linux musl 目标需要 `musl-tools` 包；i686 目标需要 `gcc-i686-linux-gnu`。

## 使用方法

```bash
ns-sandbox [选项] "命令"
```

### 选项

| 参数 | 说明 |
|------|------|
| `--yes` | 自动确认所有提示 |
| `--allow-network` | 允许网络访问 |
| `--allow-system-write` | 允许写入系统目录 |
| `--allow-write <PATH>` | 允许写入指定路径 |
| `--timeout <SEC>` | CPU 超时秒数 (0=不限) |
| `--memory-limit <MB>` | 内存限制 (0=不限) |
| `--read-only` | 只读文件系统 |
| `--process-limit <N>` | 子进程数量限制 (0=不限) |

### 示例

```bash
# 基本使用
ns-sandbox "echo hello world"

# 允许网络和额外写路径
ns-sandbox --allow-network --allow-write /home/user/output "python3 download.py"

# 严格隔离：只读 + 10秒超时 + 100MB内存限制
ns-sandbox --read-only --timeout 10 --memory-limit 100 "untrusted-binary"

# 支持引号包裹的参数
ns-sandbox "cat \"/path/with spaces/file.txt\""

# 自动确认危险命令
ns-sandbox --yes "rm -rf /tmp/test"
```

## 平台隔离机制

### Linux

| 机制 | 状态 |
|------|------|
| PID namespace | ✅ 进程树隔离 |
| NET namespace | ✅ 网络隔离 (条件) |
| IPC namespace | ✅ 进程间通信隔离 |
| UTS namespace | ✅ 主机名隔离 |
| Mount namespace | ✅ 私有 `/proc` `/tmp` `/dev` `/run` |
| User namespace | ✅ 非特权容器 (尝试) |
| Seccomp BPF | ✅ 阻止 15 个危险系统调用 |
| Capability bounding | ✅ 清空 capability set |
| NO_NEW_PRIVS | ✅ 阻止提权 |
| RLIMIT_CPU/AS/NPROC | ✅ 资源限制 |

> 需要 `CONFIG_USER_NS` 内核选项或 root 权限。

### macOS

| 机制 | 状态 |
|------|------|
| sandbox-exec SBPL | ✅ 文件读写/网络/IPC/IOKit 策略 |
| Mach IPC 限制 | ✅ `(deny mach-lookup)` |
| Apple Events | ✅ `(deny appleevent-send)` |
| IOKit 限制 | ✅ `(deny iokit-open)` |
| 敏感文件读保护 | ✅ 阻止读取 `/etc/shadow`、`/Users` 等 |
| setrlimit fallback | ✅ sandbox-exec 不可用时降级 |

### Windows

| 机制 | 状态 |
|------|------|
| Job Objects | ✅ 进程隔离 + 自动清理 |
| 内存限制 | ✅ `JOB_OBJECT_LIMIT_PROCESS_MEMORY` |
| 进程数限制 | ✅ `JOB_OBJECT_LIMIT_ACTIVE_PROCESS` |
| 超时控制 | ✅ `JOB_OBJECT_LIMIT_JOB_TIME` |

## CI/CD 流水线

项目使用 GitHub Actions 自动构建和发布。

GitHub 官方 hosted runner 支持 **Ubuntu** 系列操作系统（22.04/24.04/26.04，含 x64 + ARM64）。Rust 交叉编译可构建任意目标平台产物。

### 构建目标

| 目标 | 架构 | 运行平台 | 链接方式 |
|------|------|----------|----------|
| `x86_64-unknown-linux-gnu` | x86_64 | ubuntu-latest | glibc 动态 |
| `x86_64-unknown-linux-musl` | x86_64 | ubuntu-latest | musl 静态 |
| `i686-unknown-linux-gnu` | i686 (32位) | ubuntu-latest | glibc 动态 |
| `aarch64-unknown-linux-gnu` | ARM64 | ubuntu-24.04-arm | glibc 动态 |
| `aarch64-unknown-linux-musl` | ARM64 | ubuntu-24.04-arm | musl 静态 |
| `x86_64-apple-darwin` | x86_64 | macos-15-intel | 系统动态 |
| `aarch64-apple-darwin` | ARM64 | macos-latest | 系统动态 |
| `x86_64-pc-windows-msvc` | x86_64 | windows-latest | MSVC 动态 |

### 产物

- 压缩包 (`.tar.gz` / `.zip`) + SHA256 校验和
- Linux 发行版包：DEB (Debian/Ubuntu)、RPM (Fedora/RHEL)、APK (Alpine) — x86_64 和 ARM64
- 推送标签时自动创建 GitHub Release，包含全部构建产物

### 配置文件

`.github/workflows/release.yml`

## 架构

```
ns-sandbox/
├── src/
│   ├── main.rs              # 主入口、CLI 解析、命令分析
│   └── sandbox/
│       ├── mod.rs           # 沙盒模块入口 (条件编译)
│       ├── linux.rs         # Linux namespaces + seccomp
│       ├── macos.rs         # macOS sandbox-exec SBPL
│       └── windows.rs       # Windows Job Objects
├── .github/workflows/
│   └── release.yml          # CI/CD 流水线
├── Cargo.toml
└── README.md
```

## 依赖

- `clap` — CLI 参数解析
- `anyhow` — 错误处理
- `shell-words` — 命令引用解析
- `libc` — Unix 系统调用 (Linux/macOS)
- `nix` — Linux 命名空间和挂载 (仅 Linux)
- `windows` — Windows API (仅 Windows)
