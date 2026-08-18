//! Default-deny seccomp policy definitions.

use std::{fmt, str::FromStr};

use crate::IsolationError;

/// A syscall name that can be considered for the seccomp allowlist.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Syscall {
    /// Read bytes from a file descriptor.
    Read,
    /// Write bytes to a file descriptor.
    Write,
    /// Close a file descriptor.
    Close,
    /// Wait for activity on an already-open file descriptor.
    Poll,
    /// Read file metadata.
    Fstat,
    /// Read file metadata relative to a directory descriptor.
    Newfstatat,
    /// Create a memory mapping.
    Mmap,
    /// Change memory protection.
    Mprotect,
    /// Remove a memory mapping.
    Munmap,
    /// Advise the kernel about memory usage.
    Madvise,
    /// Expand the process heap.
    Brk,
    /// Install a signal handler.
    RtSigaction,
    /// Change the signal mask.
    RtSigprocmask,
    /// Return from a signal handler.
    RtSigreturn,
    /// Position-independent read.
    Pread64,
    /// Position-independent write.
    Pwrite64,
    /// Read a directory stream.
    Getdents64,
    /// Change the current working directory.
    Chdir,
    /// Read the current working directory.
    Getcwd,
    /// Open a path relative to a directory descriptor.
    Openat,
    /// Create a directory by path.
    Mkdir,
    /// Create a directory relative to a directory descriptor.
    Mkdirat,
    /// Remove a non-directory path.
    Unlink,
    /// Remove a path relative to a directory descriptor.
    Unlinkat,
    /// Remove an empty directory by path.
    Rmdir,
    /// Rename paths.
    Rename,
    /// Rename paths relative to directory descriptors.
    Renameat,
    /// Create a hard link relative to directory descriptors.
    Linkat,
    /// Create a symbolic link by path.
    Symlink,
    /// Create a symbolic link relative to a directory descriptor.
    Symlinkat,
    /// Read a symbolic-link target by path.
    Readlink,
    /// Read a link target relative to a directory descriptor.
    Readlinkat,
    /// Change file mode by path.
    Chmod,
    /// Change file mode through a descriptor.
    Fchmod,
    /// Change file mode relative to a directory descriptor.
    Fchmodat,
    /// Change the file size through a descriptor.
    Ftruncate,
    /// Query a file with extended metadata.
    Statx,
    /// Replace the current image.
    Execve,
    /// Replace the current image relative to a descriptor.
    Execveat,
    /// Wait for a child process.
    Wait4,
    /// Block on a futex.
    Futex,
    /// Yield the scheduler.
    SchedYield,
    /// Read a monotonic clock.
    ClockGettime,
    /// Read the current process identifier.
    Getpid,
    /// Read the current thread identifier.
    Gettid,
    /// Read the process CPU-affinity mask.
    SchedGetaffinity,
    /// Configure the current thread's alternate signal stack.
    Sigaltstack,
    /// Fill a buffer with kernel random bytes.
    Getrandom,
    /// Set the robust futex list.
    SetRobustList,
    /// Set the thread identifier address.
    SetTidAddress,
    /// Register a restartable sequence area.
    Rseq,
    /// Set process resource limits.
    Prlimit64,
    /// Set the architecture-specific thread state.
    ArchPrctl,
    /// Exit the current thread.
    Exit,
    /// Exit the entire process.
    ExitGroup,
    /// Create a socket; always forbidden by this policy.
    Socket,
    /// Connect a socket; always forbidden by this policy.
    Connect,
    /// Bind a socket; always forbidden by this policy.
    Bind,
    /// Listen on a socket; always forbidden by this policy.
    Listen,
    /// Accept a socket; always forbidden by this policy.
    Accept,
    /// Accept a socket with flags; always forbidden by this policy.
    Accept4,
    /// Send a datagram; always forbidden by this policy.
    Sendto,
    /// Send a message; always forbidden by this policy.
    Sendmsg,
    /// Receive a datagram; always forbidden by this policy.
    Recvfrom,
    /// Receive a message; always forbidden by this policy.
    Recvmsg,
    /// Create a socket pair; always forbidden by this policy.
    Socketpair,
    /// Mount a filesystem; always forbidden by this policy.
    Mount,
    /// Unmount a filesystem; always forbidden by this policy.
    Umount2,
    /// Create a namespace; always forbidden by this policy.
    Unshare,
    /// Join a namespace; always forbidden by this policy.
    Setns,
    /// Trace another process; always forbidden by this policy.
    Ptrace,
    /// Read another process memory; always forbidden by this policy.
    ProcessVmReadv,
    /// Write another process memory; always forbidden by this policy.
    ProcessVmWritev,
    /// Load an eBPF program; always forbidden by this policy.
    Bpf,
    /// Open a performance event; always forbidden by this policy.
    PerfEventOpen,
    /// Access a device through ioctl; always forbidden by this policy.
    Ioctl,
    /// Move the process root; always forbidden by this policy.
    PivotRoot,
    /// Change the process root; always forbidden by this policy.
    Chroot,
    /// Create a process; always forbidden by this policy.
    Clone,
    /// Create a process with clone3; always forbidden by this policy.
    Clone3,
    /// Fork a process; always forbidden by this policy.
    Fork,
    /// Fork a process with vfork; always forbidden by this policy.
    Vfork,
    /// Create a device node; always forbidden by this policy.
    Mknod,
    /// Create a device node relative to a directory descriptor; always forbidden by this policy.
    Mknodat,
    /// Create a System V shared-memory segment; always forbidden by this policy.
    Shmget,
    /// Attach a System V shared-memory segment; always forbidden by this policy.
    Shmat,
    /// Control a System V shared-memory segment; always forbidden by this policy.
    Shmctl,
    /// Detach a System V shared-memory segment; always forbidden by this policy.
    Shmdt,
    /// Load a kernel module; always forbidden by this policy.
    InitModule,
    /// Delete a kernel module; always forbidden by this policy.
    DeleteModule,
    /// Load a kernel module from a file; always forbidden by this policy.
    FinitModule,
    /// Load a new kernel image; always forbidden by this policy.
    KexecLoad,
    /// Load a new kernel image from a file; always forbidden by this policy.
    KexecFileLoad,
    /// Add a kernel key; always forbidden by this policy.
    AddKey,
    /// Request a kernel key; always forbidden by this policy.
    RequestKey,
    /// Operate on kernel keys; always forbidden by this policy.
    Keyctl,
    /// Initialize filesystem notification; always forbidden by this policy.
    FanotifyInit,
    /// Add a filesystem notification mark; always forbidden by this policy.
    FanotifyMark,
    /// Resolve a file handle; always forbidden by this policy.
    NameToHandleAt,
    /// Open a file handle; always forbidden by this policy.
    OpenByHandleAt,
    /// Compare process resources; always forbidden by this policy.
    Kcmp,
    /// Create a userfaultfd; always forbidden by this policy.
    Userfaultfd,
    /// Send a signal through a pidfd; always forbidden by this policy.
    PidfdSendSignal,
    /// Open a pidfd; always forbidden by this policy.
    PidfdOpen,
    /// Duplicate a descriptor through a pidfd; always forbidden by this policy.
    PidfdGetfd,
    /// Advise the kernel about another process's memory; always forbidden by this policy.
    ProcessMadvise,
    /// Release another process's memory; always forbidden by this policy.
    ProcessMrelease,
    /// Enter an `io_uring` instance; always forbidden by this policy.
    IoUringSetup,
    /// Submit work through `io_uring`; always forbidden by this policy.
    IoUringEnter,
    /// Register resources with `io_uring`; always forbidden by this policy.
    IoUringRegister,
    /// Open a filesystem mount tree; always forbidden by this policy.
    OpenTree,
    /// Move a mount; always forbidden by this policy.
    MoveMount,
    /// Open a filesystem context; always forbidden by this policy.
    Fsopen,
    /// Configure a filesystem context; always forbidden by this policy.
    Fsconfig,
    /// Create a mount from a filesystem context; always forbidden by this policy.
    Fsmount,
    /// Pick an existing filesystem context; always forbidden by this policy.
    Fspick,
    /// Change mount attributes; always forbidden by this policy.
    MountSetattr,
    /// Change the system hostname; always forbidden by this policy.
    Sethostname,
    /// Change the system domain name; always forbidden by this policy.
    Setdomainname,
    /// Reboot the system; always forbidden by this policy.
    Reboot,
    /// Enable swapping; always forbidden by this policy.
    Swapon,
    /// Disable swapping; always forbidden by this policy.
    Swapoff,
    /// Read or clear the kernel log; always forbidden by this policy.
    Syslog,
    /// Set process personality flags; always forbidden by this policy.
    Personality,
    /// Change process credentials; always forbidden by this policy.
    Setuid,
    /// Change process group credentials; always forbidden by this policy.
    Setgid,
    /// Change real and effective user IDs; always forbidden by this policy.
    Setreuid,
    /// Change real and effective group IDs; always forbidden by this policy.
    Setregid,
    /// Change supplementary groups; always forbidden by this policy.
    Setgroups,
    /// Change real, effective, and saved user IDs; always forbidden by this policy.
    Setresuid,
    /// Change real, effective, and saved group IDs; always forbidden by this policy.
    Setresgid,
    /// Change the filesystem user ID; always forbidden by this policy.
    Setfsuid,
    /// Change the filesystem group ID; always forbidden by this policy.
    Setfsgid,
    /// Change process capabilities; always forbidden by this policy.
    Capset,
    /// Change process control attributes; always forbidden by this policy.
    Prctl,
    /// Install another seccomp filter; always forbidden by this policy.
    Seccomp,
}

impl Syscall {
    pub(crate) const fn is_forbidden(self) -> bool {
        matches!(
            self,
            Self::Socket
                | Self::Connect
                | Self::Bind
                | Self::Listen
                | Self::Accept
                | Self::Accept4
                | Self::Sendto
                | Self::Sendmsg
                | Self::Recvfrom
                | Self::Recvmsg
                | Self::Socketpair
                | Self::Mount
                | Self::Umount2
                | Self::Unshare
                | Self::Setns
                | Self::Ptrace
                | Self::ProcessVmReadv
                | Self::ProcessVmWritev
                | Self::Bpf
                | Self::PerfEventOpen
                | Self::Ioctl
                | Self::PivotRoot
                | Self::Chroot
                | Self::Clone
                | Self::Clone3
                | Self::Fork
                | Self::Vfork
                | Self::Mknod
                | Self::Mknodat
                | Self::Shmget
                | Self::Shmat
                | Self::Shmctl
                | Self::Shmdt
                | Self::InitModule
                | Self::DeleteModule
                | Self::FinitModule
                | Self::KexecLoad
                | Self::KexecFileLoad
                | Self::AddKey
                | Self::RequestKey
                | Self::Keyctl
                | Self::FanotifyInit
                | Self::FanotifyMark
                | Self::NameToHandleAt
                | Self::OpenByHandleAt
                | Self::Kcmp
                | Self::Userfaultfd
                | Self::PidfdSendSignal
                | Self::PidfdOpen
                | Self::PidfdGetfd
                | Self::ProcessMadvise
                | Self::ProcessMrelease
                | Self::IoUringSetup
                | Self::IoUringEnter
                | Self::IoUringRegister
                | Self::OpenTree
                | Self::MoveMount
                | Self::Fsopen
                | Self::Fsconfig
                | Self::Fsmount
                | Self::Fspick
                | Self::MountSetattr
                | Self::Sethostname
                | Self::Setdomainname
                | Self::Reboot
                | Self::Swapon
                | Self::Swapoff
                | Self::Syslog
                | Self::Personality
                | Self::Setuid
                | Self::Setgid
                | Self::Setreuid
                | Self::Setregid
                | Self::Setgroups
                | Self::Setresuid
                | Self::Setresgid
                | Self::Setfsuid
                | Self::Setfsgid
                | Self::Capset
                | Self::Prctl
                | Self::Seccomp
        )
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) const fn number(self) -> Option<i32> {
        Some(match self {
            Self::Read => 0,
            Self::Write => 1,
            Self::Close => 3,
            Self::Poll => 7,
            Self::Fstat => 5,
            Self::Newfstatat => 262,
            Self::Mmap => 9,
            Self::Mprotect => 10,
            Self::Munmap => 11,
            Self::Madvise => 28,
            Self::Brk => 12,
            Self::RtSigaction => 13,
            Self::RtSigprocmask => 14,
            Self::RtSigreturn => 15,
            Self::Pread64 => 17,
            Self::Pwrite64 => 18,
            Self::Getdents64 => 217,
            Self::Chdir => 80,
            Self::Getcwd => 79,
            Self::Openat => 257,
            Self::Mkdir => 83,
            Self::Mkdirat => 258,
            Self::Unlink => 87,
            Self::Unlinkat => 263,
            Self::Rmdir => 84,
            Self::Rename => 82,
            Self::Renameat => 264,
            Self::Linkat => 265,
            Self::Symlink => 88,
            Self::Symlinkat => 266,
            Self::Readlink => 89,
            Self::Readlinkat => 267,
            Self::Chmod => 90,
            Self::Fchmod => 91,
            Self::Fchmodat => 268,
            Self::Ftruncate => 77,
            Self::Statx => 332,
            Self::Execve => 59,
            Self::Execveat => 322,
            Self::Wait4 => 61,
            Self::Futex => 202,
            Self::SchedYield => 24,
            Self::ClockGettime => 228,
            Self::Getpid => 39,
            Self::Gettid => 186,
            Self::SchedGetaffinity => 204,
            Self::Sigaltstack => 131,
            Self::Getrandom => 318,
            Self::SetRobustList => 273,
            Self::SetTidAddress => 218,
            Self::Rseq => 334,
            Self::Prlimit64 => 302,
            Self::ArchPrctl => 158,
            Self::Exit => 60,
            Self::ExitGroup => 231,
            _ => return None,
        })
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) const fn number(self) -> Option<i32> {
        // Linux aarch64 follows asm-generic/unistd.h and intentionally omits
        // several legacy path-only syscalls. Its libc wrappers use the *at
        // forms included here.
        Some(match self {
            Self::Read => 63,
            Self::Write => 64,
            Self::Close => 57,
            Self::Poll => 73,
            Self::Fstat => 80,
            Self::Newfstatat => 79,
            Self::Mmap => 222,
            Self::Mprotect => 226,
            Self::Munmap => 215,
            Self::Madvise => 233,
            Self::Brk => 214,
            Self::RtSigaction => 134,
            Self::RtSigprocmask => 135,
            Self::RtSigreturn => 139,
            Self::Pread64 => 67,
            Self::Pwrite64 => 68,
            Self::Getdents64 => 61,
            Self::Chdir => 49,
            Self::Getcwd => 17,
            Self::Openat => 56,
            Self::Mkdirat => 34,
            Self::Unlinkat => 35,
            Self::Renameat => 38,
            Self::Linkat => 37,
            Self::Symlinkat => 36,
            Self::Readlinkat => 78,
            Self::Fchmod => 52,
            Self::Fchmodat => 53,
            Self::Ftruncate => 46,
            Self::Statx => 291,
            Self::Execve => 221,
            Self::Execveat => 281,
            Self::Wait4 => 260,
            Self::Futex => 98,
            Self::SchedYield => 124,
            Self::ClockGettime => 113,
            Self::Getpid => 172,
            Self::Gettid => 178,
            Self::SchedGetaffinity => 123,
            Self::Sigaltstack => 132,
            Self::Getrandom => 278,
            Self::SetRobustList => 99,
            Self::SetTidAddress => 96,
            Self::Rseq => 293,
            Self::Prlimit64 => 261,
            Self::Exit => 93,
            Self::ExitGroup => 94,
            _ => return None,
        })
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub(crate) const fn number(self) -> Option<i32> {
        let _ = self;
        None
    }
}

impl fmt::Display for Syscall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl FromStr for Syscall {
    type Err = IsolationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.to_ascii_lowercase();
        let syscall = match normalized.as_str() {
            "read" => Self::Read,
            "write" => Self::Write,
            "close" => Self::Close,
            "poll" => Self::Poll,
            "fstat" => Self::Fstat,
            "newfstatat" => Self::Newfstatat,
            "mmap" => Self::Mmap,
            "mprotect" => Self::Mprotect,
            "munmap" => Self::Munmap,
            "madvise" => Self::Madvise,
            "brk" => Self::Brk,
            "rt_sigaction" => Self::RtSigaction,
            "rt_sigprocmask" => Self::RtSigprocmask,
            "rt_sigreturn" => Self::RtSigreturn,
            "pread64" => Self::Pread64,
            "pwrite64" => Self::Pwrite64,
            "getdents64" => Self::Getdents64,
            "chdir" => Self::Chdir,
            "getcwd" => Self::Getcwd,
            "openat" => Self::Openat,
            "mkdir" => Self::Mkdir,
            "mkdirat" => Self::Mkdirat,
            "unlink" => Self::Unlink,
            "unlinkat" => Self::Unlinkat,
            "rmdir" => Self::Rmdir,
            "rename" => Self::Rename,
            "renameat" => Self::Renameat,
            "linkat" => Self::Linkat,
            "symlink" => Self::Symlink,
            "symlinkat" => Self::Symlinkat,
            "readlink" => Self::Readlink,
            "readlinkat" => Self::Readlinkat,
            "chmod" => Self::Chmod,
            "fchmod" => Self::Fchmod,
            "fchmodat" => Self::Fchmodat,
            "ftruncate" => Self::Ftruncate,
            "statx" => Self::Statx,
            "execve" => Self::Execve,
            "execveat" => Self::Execveat,
            "wait4" => Self::Wait4,
            "futex" => Self::Futex,
            "sched_yield" => Self::SchedYield,
            "clock_gettime" => Self::ClockGettime,
            "getpid" => Self::Getpid,
            "gettid" => Self::Gettid,
            "sched_getaffinity" => Self::SchedGetaffinity,
            "sigaltstack" => Self::Sigaltstack,
            "getrandom" => Self::Getrandom,
            "set_robust_list" => Self::SetRobustList,
            "set_tid_address" => Self::SetTidAddress,
            "rseq" => Self::Rseq,
            "prlimit64" => Self::Prlimit64,
            "arch_prctl" => Self::ArchPrctl,
            "exit" => Self::Exit,
            "exit_group" => Self::ExitGroup,
            _ => parse_forbidden_syscall(normalized.as_str()).ok_or_else(|| {
                IsolationError::InvalidConfig(format!(
                    "unknown syscall '{value}' is not in the explicit allowlist"
                ))
            })?,
        };
        Ok(syscall)
    }
}

fn parse_forbidden_syscall(value: &str) -> Option<Syscall> {
    Some(match value {
        "socket" => Syscall::Socket,
        "connect" => Syscall::Connect,
        "bind" => Syscall::Bind,
        "listen" => Syscall::Listen,
        "accept" => Syscall::Accept,
        "accept4" => Syscall::Accept4,
        "sendto" => Syscall::Sendto,
        "sendmsg" => Syscall::Sendmsg,
        "recvfrom" => Syscall::Recvfrom,
        "recvmsg" => Syscall::Recvmsg,
        "socketpair" => Syscall::Socketpair,
        "mount" => Syscall::Mount,
        "umount2" => Syscall::Umount2,
        "unshare" => Syscall::Unshare,
        "setns" => Syscall::Setns,
        "ptrace" => Syscall::Ptrace,
        "process_vm_readv" => Syscall::ProcessVmReadv,
        "process_vm_writev" => Syscall::ProcessVmWritev,
        "bpf" => Syscall::Bpf,
        "perf_event_open" => Syscall::PerfEventOpen,
        "ioctl" => Syscall::Ioctl,
        "pivot_root" => Syscall::PivotRoot,
        "chroot" => Syscall::Chroot,
        "clone" => Syscall::Clone,
        "clone3" => Syscall::Clone3,
        "fork" => Syscall::Fork,
        "vfork" => Syscall::Vfork,
        "mknod" => Syscall::Mknod,
        "mknodat" => Syscall::Mknodat,
        "shmget" => Syscall::Shmget,
        "shmat" => Syscall::Shmat,
        "shmctl" => Syscall::Shmctl,
        "shmdt" => Syscall::Shmdt,
        "init_module" => Syscall::InitModule,
        "delete_module" => Syscall::DeleteModule,
        "finit_module" => Syscall::FinitModule,
        "kexec_load" => Syscall::KexecLoad,
        "kexec_file_load" => Syscall::KexecFileLoad,
        "add_key" => Syscall::AddKey,
        "request_key" => Syscall::RequestKey,
        "keyctl" => Syscall::Keyctl,
        "fanotify_init" => Syscall::FanotifyInit,
        "fanotify_mark" => Syscall::FanotifyMark,
        "name_to_handle_at" => Syscall::NameToHandleAt,
        "open_by_handle_at" => Syscall::OpenByHandleAt,
        "kcmp" => Syscall::Kcmp,
        "userfaultfd" => Syscall::Userfaultfd,
        "pidfd_send_signal" => Syscall::PidfdSendSignal,
        "pidfd_open" => Syscall::PidfdOpen,
        "pidfd_getfd" => Syscall::PidfdGetfd,
        "process_madvise" => Syscall::ProcessMadvise,
        "process_mrelease" => Syscall::ProcessMrelease,
        "io_uring_setup" => Syscall::IoUringSetup,
        "io_uring_enter" => Syscall::IoUringEnter,
        "io_uring_register" => Syscall::IoUringRegister,
        "open_tree" => Syscall::OpenTree,
        "move_mount" => Syscall::MoveMount,
        "fsopen" => Syscall::Fsopen,
        "fsconfig" => Syscall::Fsconfig,
        "fsmount" => Syscall::Fsmount,
        "fspick" => Syscall::Fspick,
        "mount_setattr" => Syscall::MountSetattr,
        "sethostname" => Syscall::Sethostname,
        "setdomainname" => Syscall::Setdomainname,
        "reboot" => Syscall::Reboot,
        "swapon" => Syscall::Swapon,
        "swapoff" => Syscall::Swapoff,
        "syslog" => Syscall::Syslog,
        "personality" => Syscall::Personality,
        "setuid" => Syscall::Setuid,
        "setgid" => Syscall::Setgid,
        "setreuid" => Syscall::Setreuid,
        "setregid" => Syscall::Setregid,
        "setgroups" => Syscall::Setgroups,
        "setresuid" => Syscall::Setresuid,
        "setresgid" => Syscall::Setresgid,
        "setfsuid" => Syscall::Setfsuid,
        "setfsgid" => Syscall::Setfsgid,
        "capset" => Syscall::Capset,
        "prctl" => Syscall::Prctl,
        "seccomp" => Syscall::Seccomp,
        _ => return None,
    })
}

/// An explicit default-deny seccomp policy.
#[derive(Clone, Debug)]
pub struct SeccompPolicy {
    pub(crate) allowed: Vec<Syscall>,
}

impl SeccompPolicy {
    /// Builds a policy and rejects dangerous or empty allowlists.
    pub fn new<I>(syscalls: I) -> Result<Self, IsolationError>
    where
        I: IntoIterator<Item = Syscall>,
    {
        let mut allowed: Vec<_> = syscalls.into_iter().collect();
        if allowed.is_empty() {
            return Err(IsolationError::InvalidConfig(
                "seccomp allowlist must not be empty; default deny would make the workload unstartable"
                    .to_owned(),
            ));
        }
        if let Some(forbidden) = allowed
            .iter()
            .copied()
            .find(|syscall| syscall.is_forbidden())
        {
            return Err(IsolationError::ForbiddenSyscall(forbidden));
        }
        allowed.sort_unstable();
        allowed.dedup();
        Ok(Self { allowed })
    }

    /// Returns a conservative allowlist for a dynamically linked workload.
    pub fn conservative() -> Self {
        Self {
            allowed: vec![
                Syscall::Read,
                Syscall::Write,
                Syscall::Close,
                Syscall::Poll,
                Syscall::Fstat,
                Syscall::Newfstatat,
                Syscall::Mmap,
                Syscall::Mprotect,
                Syscall::Munmap,
                Syscall::Madvise,
                Syscall::Brk,
                Syscall::RtSigaction,
                Syscall::RtSigprocmask,
                Syscall::RtSigreturn,
                Syscall::Pread64,
                Syscall::Pwrite64,
                Syscall::Getdents64,
                Syscall::Chdir,
                Syscall::Getcwd,
                Syscall::Openat,
                Syscall::Mkdir,
                Syscall::Mkdirat,
                Syscall::Unlink,
                Syscall::Unlinkat,
                Syscall::Rmdir,
                Syscall::Rename,
                Syscall::Renameat,
                Syscall::Linkat,
                Syscall::Symlink,
                Syscall::Symlinkat,
                Syscall::Readlink,
                Syscall::Readlinkat,
                Syscall::Chmod,
                Syscall::Fchmod,
                Syscall::Fchmodat,
                Syscall::Ftruncate,
                Syscall::Statx,
                Syscall::Execve,
                Syscall::Execveat,
                Syscall::Wait4,
                Syscall::Futex,
                Syscall::SchedYield,
                Syscall::ClockGettime,
                Syscall::Getpid,
                Syscall::Gettid,
                Syscall::SchedGetaffinity,
                Syscall::Sigaltstack,
                Syscall::Getrandom,
                Syscall::SetRobustList,
                Syscall::SetTidAddress,
                Syscall::Rseq,
                Syscall::Prlimit64,
                Syscall::ArchPrctl,
                Syscall::Exit,
                Syscall::ExitGroup,
            ]
            .into_iter()
            .filter(|syscall| syscall.number().is_some())
            .collect(),
        }
    }

    /// Returns whether a syscall is explicitly allowed.
    pub fn allows(&self, syscall: Syscall) -> bool {
        self.allowed.binary_search(&syscall).is_ok()
    }

    /// Returns the ordered allowlist.
    pub fn allowed_syscalls(&self) -> &[Syscall] {
        &self.allowed
    }

    pub(crate) fn validate_for_platform(&self) -> Result<(), IsolationError> {
        if let Some(syscall) = self
            .allowed
            .iter()
            .copied()
            .find(|syscall| syscall.number().is_none())
        {
            return Err(IsolationError::UnsupportedSyscall(syscall));
        }
        Ok(())
    }
}

impl Default for SeccompPolicy {
    fn default() -> Self {
        Self::conservative()
    }
}
