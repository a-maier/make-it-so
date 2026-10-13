use std::{
    ffi::OsString, fs::read_link, os::unix::ffi::OsStringExt, path::PathBuf,
};

use log::trace;
use pete::Tracee;

use crate::{RunError, SyscallHandleError};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) enum SyscallAction {
    AddDependency(PathBuf),
    AddDependencyPair(PathBuf, PathBuf),
}

pub(crate) use target_syscalls::handle_syscall;

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub(crate) mod target_syscalls {

    use log::{error, warn};

    use crate::SyscallHandleError;

    use super::*;

    use derive_more::{Display, TryFrom};

    #[derive(
        Copy,
        Clone,
        Debug,
        Eq,
        PartialEq,
        Ord,
        PartialOrd,
        Hash,
        Display,
        TryFrom,
    )]
    #[try_from(repr)]
    #[repr(u64)]
    #[display(rename_all = "snake_case")]
    enum Syscall {
        Read = 0,
        Write = 1,
        Open = 2,
        Close = 3,
        Stat = 4,
        Fstat = 5,
        Lstat = 6,
        Poll = 7,
        Lseek = 8,
        Mmap = 9,
        Mprotect = 10,
        Munmap = 11,
        Brk = 12,
        RtSigaction = 13,
        RtSigprocmask = 14,
        RtSigreturn = 15,
        Ioctl = 16,
        Pread64 = 17,
        Pwrite64 = 18,
        Readv = 19,
        Writev = 20,
        Access = 21,
        Pipe = 22,
        Select = 23,
        SchedYield = 24,
        Mremap = 25,
        Msync = 26,
        Mincore = 27,
        Madvise = 28,
        Shmget = 29,
        Shmat = 30,
        Shmctl = 31,
        Dup = 32,
        Dup2 = 33,
        Pause = 34,
        Nanosleep = 35,
        Getitimer = 36,
        Alarm = 37,
        Setitimer = 38,
        Getpid = 39,
        Sendfile64 = 40,
        Socket = 41,
        Connect = 42,
        Accept = 43,
        Sendto = 44,
        Recvfrom = 45,
        Sendmsg = 46,
        Recvmsg = 47,
        Shutdown = 48,
        Bind = 49,
        Listen = 50,
        Getsockname = 51,
        Getpeername = 52,
        Socketpair = 53,
        Setsockopt = 54,
        Getsockopt = 55,
        Clone = 56,
        Fork = 57,
        Vfork = 58,
        Execve = 59,
        Exit = 60,
        Wait4 = 61,
        Kill = 62,
        Newuname = 63,
        Semget = 64,
        Semop = 65,
        Semctl = 66,
        Shmdt = 67,
        Msgget = 68,
        Msgsnd = 69,
        Msgrcv = 70,
        Msgctl = 71,
        Fcntl = 72,
        Flock = 73,
        Fsync = 74,
        Fdatasync = 75,
        Truncate = 76,
        Ftruncate = 77,
        Getdents = 78,
        Getcwd = 79,
        Chdir = 80,
        Fchdir = 81,
        Rename = 82,
        Mkdir = 83,
        Rmdir = 84,
        Creat = 85,
        Link = 86,
        Unlink = 87,
        Symlink = 88,
        Readlink = 89,
        Chmod = 90,
        Fchmod = 91,
        Chown = 92,
        Fchown = 93,
        Lchown = 94,
        Umask = 95,
        Gettimeofday = 96,
        Getrlimit = 97,
        Getrusage = 98,
        Sysinfo = 99,
        Times = 100,
        Ptrace = 101,
        Getuid = 102,
        Syslog = 103,
        Getgid = 104,
        Setuid = 105,
        Setgid = 106,
        Geteuid = 107,
        Getegid = 108,
        Setpgid = 109,
        Getppid = 110,
        Getpgrp = 111,
        Setsid = 112,
        Setreuid = 113,
        Setregid = 114,
        Getgroups = 115,
        Setgroups = 116,
        Setresuid = 117,
        Getresuid = 118,
        Setresgid = 119,
        Getresgid = 120,
        Getpgid = 121,
        Setfsuid = 122,
        Setfsgid = 123,
        Getsid = 124,
        Capget = 125,
        Capset = 126,
        RtSigpending = 127,
        RtSigtimedwait = 128,
        RtSigqueueinfo = 129,
        RtSigsuspend = 130,
        Sigaltstack = 131,
        Utime = 132,
        Mknod = 133,
        Personality = 135,
        Ustat = 136,
        Statfs = 137,
        Fstatfs = 138,
        Sysfs = 139,
        Getpriority = 140,
        Setpriority = 141,
        SchedSetparam = 142,
        SchedGetparam = 143,
        SchedSetscheduler = 144,
        SchedGetscheduler = 145,
        SchedGetPriorityMax = 146,
        SchedGetPriorityMin = 147,
        SchedRrGetInterval = 148,
        Mlock = 149,
        Munlock = 150,
        Mlockall = 151,
        Munlockall = 152,
        Vhangup = 153,
        ModifyLdt = 154,
        PivotRoot = 155,
        Prctl = 157,
        ArchPrctl = 158,
        Adjtimex = 159,
        Setrlimit = 160,
        Chroot = 161,
        Sync = 162,
        Acct = 163,
        Settimeofday = 164,
        Mount = 165,
        Umount = 166,
        Swapon = 167,
        Swapoff = 168,
        Reboot = 169,
        Sethostname = 170,
        Setdomainname = 171,
        Iopl = 172,
        Ioperm = 173,
        InitModule = 175,
        DeleteModule = 176,
        Quotactl = 179,
        Gettid = 186,
        Readahead = 187,
        Setxattr = 188,
        Lsetxattr = 189,
        Fsetxattr = 190,
        Getxattr = 191,
        Lgetxattr = 192,
        Fgetxattr = 193,
        Listxattr = 194,
        Llistxattr = 195,
        Flistxattr = 196,
        Removexattr = 197,
        Lremovexattr = 198,
        Fremovexattr = 199,
        Tkill = 200,
        Time = 201,
        Futex = 202,
        SchedSetaffinity = 203,
        SchedGetaffinity = 204,
        IoSetup = 206,
        IoDestroy = 207,
        IoGetevents = 208,
        IoSubmit = 209,
        IoCancel = 210,
        EpollCreate = 213,
        RemapFilePages = 216,
        Getdents64 = 217,
        SetTidAddress = 218,
        #[allow(clippy::enum_variant_names)]
        RestartSyscall = 219,
        Semtimedop = 220,
        Fadvise64 = 221,
        TimerCreate = 222,
        TimerSettime = 223,
        TimerGettime = 224,
        TimerGetoverrun = 225,
        TimerDelete = 226,
        ClockSettime = 227,
        ClockGettime = 228,
        ClockGetres = 229,
        ClockNanosleep = 230,
        ExitGroup = 231,
        EpollWait = 232,
        EpollCtl = 233,
        Tgkill = 234,
        Utimes = 235,
        Mbind = 237,
        SetMempolicy = 238,
        GetMempolicy = 239,
        MqOpen = 240,
        MqUnlink = 241,
        MqTimedsend = 242,
        MqTimedreceive = 243,
        MqNotify = 244,
        MqGetsetattr = 245,
        KexecLoad = 246,
        Waitid = 247,
        AddKey = 248,
        RequestKey = 249,
        Keyctl = 250,
        IoprioSet = 251,
        IoprioGet = 252,
        InotifyInit = 253,
        InotifyAddWatch = 254,
        InotifyRmWatch = 255,
        MigratePages = 256,
        Openat = 257,
        Mkdirat = 258,
        Mknodat = 259,
        Fchownat = 260,
        Futimesat = 261,
        Newfstatat = 262,
        Unlinkat = 263,
        Renameat = 264,
        Linkat = 265,
        Symlinkat = 266,
        Readlinkat = 267,
        Fchmodat = 268,
        Faccessat = 269,
        Pselect6 = 270,
        Ppoll = 271,
        Unshare = 272,
        SetRobustList = 273,
        GetRobustList = 274,
        Splice = 275,
        Tee = 276,
        SyncFileRange = 277,
        Vmsplice = 278,
        MovePages = 279,
        Utimensat = 280,
        EpollPwait = 281,
        Signalfd = 282,
        TimerfdCreate = 283,
        Eventfd = 284,
        Fallocate = 285,
        TimerfdSettime = 286,
        TimerfdGettime = 287,
        Accept4 = 288,
        Signalfd4 = 289,
        Eventfd2 = 290,
        EpollCreate1 = 291,
        Dup3 = 292,
        Pipe2 = 293,
        InotifyInit1 = 294,
        Preadv = 295,
        Pwritev = 296,
        RtTgsigqueueinfo = 297,
        PerfEventOpen = 298,
        Recvmmsg = 299,
        FanotifyInit = 300,
        FanotifyMark = 301,
        Prlimit64 = 302,
        NameToHandleAt = 303,
        OpenByHandleAt = 304,
        ClockAdjtime = 305,
        Syncfs = 306,
        Sendmmsg = 307,
        Setns = 308,
        Getcpu = 309,
        ProcessVmReadv = 310,
        ProcessVmWritev = 311,
        Kcmp = 312,
        FinitModule = 313,
        SchedSetattr = 314,
        SchedGetattr = 315,
        Renameat2 = 316,
        Seccomp = 317,
        Getrandom = 318,
        MemfdCreate = 319,
        KexecFileLoad = 320,
        Bpf = 321,
        Execveat = 322,
        Userfaultfd = 323,
        Membarrier = 324,
        Mlock2 = 325,
        CopyFileRange = 326,
        Preadv2 = 327,
        Pwritev2 = 328,
        PkeyMprotect = 329,
        PkeyAlloc = 330,
        PkeyFree = 331,
        Statx = 332,
        IoPgetevents = 333,
        Rseq = 334,
        Uretprobe = 335,
        PidfdSendSignal = 424,
        IoUringSetup = 425,
        IoUringEnter = 426,
        IoUringRegister = 427,
        OpenTree = 428,
        MoveMount = 429,
        Fsopen = 430,
        Fsconfig = 431,
        Fsmount = 432,
        Fspick = 433,
        PidfdOpen = 434,
        Clone3 = 435,
        CloseRange = 436,
        Openat2 = 437,
        PidfdGetfd = 438,
        Faccessat2 = 439,
        ProcessMadvise = 440,
        EpollPwait2 = 441,
        MountSetattr = 442,
        QuotactlFd = 443,
        LandlockCreateRuleset = 444,
        LandlockAddRule = 445,
        LandlockRestrictSelf = 446,
        MemfdSecret = 447,
        ProcessMrelease = 448,
        FutexWaitv = 449,
        SetMempolicyHomeNode = 450,
        Cachestat = 451,
        Fchmodat2 = 452,
        MapShadowStack = 453,
        FutexWake = 454,
        FutexWait = 455,
        FutexRequeue = 456,
        Statmount = 457,
        Listmount = 458,
        LsmGetSelfAttr = 459,
        LsmSetSelfAttr = 460,
        LsmListModules = 461,
        Mseal = 462,
        Setxattrat = 463,
        Getxattrat = 464,
        Listxattrat = 465,
        Removexattrat = 466,
        OpenTreeAttr = 467,
        FileGetattr = 468,
        FileSetattr = 469,
    }

    fn handle_identified_syscall(
        child: &mut Tracee,
        registers: libc::user_regs_struct,
        syscall: Syscall,
    ) -> Result<Option<SyscallAction>, SyscallHandleError> {
        use Syscall::*;
        use SyscallAction::{AddDependency, AddDependencyPair};
        let res = match syscall {
            // TODO: Chdir?
            Stat | Lstat | Access | Execve | Truncate | Mkdir | Rmdir
            | Creat | Unlink | Readlink | Chmod | Chown | Lchown | Mknod
            | Setxattr | Lsetxattr | Getxattr | Lgetxattr | Listxattr
            | Llistxattr | Removexattr | Lremovexattr | Utime | Utimes => {
                let path_addr = registers.rdi;
                // TODO: how is `path_addr == 0` even possible?
                if path_addr != 0 {
                    let path = read_abs_path(child, path_addr)?;
                    trace!("Child called `{syscall}` for {path:?}");
                    Some(AddDependency(path))
                } else {
                    None
                }
            }
            Mkdirat | Mknodat | Fchownat | Futimesat | Newfstatat
            | Unlinkat | Readlinkat | Fchmodat | Utimensat | NameToHandleAt
            | Execveat => {
                let dirfd = registers.rdi as i32;
                let path_addr = registers.rsi;
                // TODO: how is `path_addr == 0` even possible?
                if path_addr != 0 {
                    let path =
                        read_abs_path_from_dirfd(child, path_addr, dirfd)?;
                    trace!("Child called `{syscall}` for {path:?}");
                    Some(AddDependency(path))
                } else {
                    None
                }
            }
            Open => {
                let path_addr = registers.rdi;
                let flags = registers.rsi as i32;
                if flags & libc::O_TMPFILE == 0 {
                    let path = read_abs_path(child, path_addr)?;
                    trace!("Child called `{syscall}` for {path:?}");
                    Some(AddDependency(path))
                } else {
                    None
                }
            }
            Openat => {
                let dirfd = registers.rdi as i32;
                let path_addr = registers.rsi;
                let flags = registers.rdx as i32;
                if flags & libc::O_TMPFILE == 0 {
                    let path =
                        read_abs_path_from_dirfd(child, path_addr, dirfd)?;
                    trace!("Child called `{syscall}` for {path:?}");
                    Some(AddDependency(path))
                } else {
                    None
                }
            }
            Statx => {
                let dirfd = registers.rdi as i32;
                let path_addr = registers.rsi;
                let flags = registers.rdx as i32;
                let path =
                    read_maybe_empty_path(child, path_addr, dirfd, flags)?;
                trace!("Child called `{syscall}` for {path:?}");
                Some(AddDependency(path))
            }
            Faccessat | Faccessat2 => {
                let dirfd = registers.rdi as i32;
                let path_addr = registers.rsi;
                let flags = registers.r10 as i32;
                let path =
                    read_maybe_empty_path(child, path_addr, dirfd, flags)?;
                trace!("Child called `{syscall}` for {path:?}");
                Some(AddDependency(path))
            }
            Openat2 => {
                warn!("Ignoring call to `{syscall}`, dependencies may be lost");
                None
            }
            Rename | Link | Symlink => {
                let from_addr = registers.rdi;
                let from_path = read_abs_path(child, from_addr)?;
                let to_addr = registers.rsi;
                let to_path = read_abs_path(child, to_addr)?;
                trace!(
                    "Child called `{syscall}` for {from_path:?} -> {to_path:?}"
                );
                Some(AddDependencyPair(from_path, to_path))
            }
            Renameat | Symlinkat | Renameat2 => {
                let from_dirfd = registers.rdi as i32;
                let from_addr = registers.rsi;
                let from_path =
                    read_abs_path_from_dirfd(child, from_addr, from_dirfd)?;
                let to_dirfd = registers.rdx as i32;
                let to_addr = registers.r10;
                let to_path =
                    read_abs_path_from_dirfd(child, to_addr, to_dirfd)?;
                trace!(
                    "Child called `{syscall}` for {from_path:?} -> {to_path:?}"
                );
                Some(AddDependencyPair(from_path, to_path))
            }
            Linkat => {
                let from_dirfd = registers.rdi as i32;
                let from_addr = registers.rsi;
                let to_dirfd = registers.rdx as i32;
                let to_addr = registers.r10;
                let flags = registers.r8 as i32;
                let from_path =
                    read_maybe_empty_path(child, from_addr, from_dirfd, flags)?;
                let to_path =
                    read_maybe_empty_path(child, to_addr, to_dirfd, flags)?;
                trace!(
                    "Child called `{syscall}` for {from_path:?} -> {to_path:?}"
                );
                Some(AddDependencyPair(from_path, to_path))
            }
            _ => {
                trace!("Ignoring syscall {syscall}");
                None
            }
        };
        Ok(res)
    }

    pub(crate) fn handle_syscall(
        child: &mut Tracee,
    ) -> Result<Option<SyscallAction>, RunError> {
        let registers = child.registers().map_err(RunError::Registers)?;
        trace!("Child registers: {registers:#?}");
        let syscall = registers.orig_rax;
        let Ok(syscall) = Syscall::try_from(syscall) else {
            error!("Encountered unknown syscall {syscall}");
            return Ok(None);
        };
        handle_identified_syscall(child, registers, syscall).map_err(|source| {
            RunError::SyscallHandle {
                syscall: syscall.to_string(),
                source,
            }
        })
    }

    fn read_maybe_empty_path(
        child: &mut Tracee,
        path_addr: u64,
        dirfd: i32,
        flags: i32,
    ) -> Result<PathBuf, SyscallHandleError> {
        if path_addr == 0 && (flags & libc::AT_EMPTY_PATH) != 0 {
            return read_dirfd_path(child, dirfd);
        }
        let mut path = read_path(child, path_addr)?;
        if path.is_empty() && (flags & libc::AT_EMPTY_PATH) != 0 {
            return read_dirfd_path(child, dirfd);
        }
        if path.is_relative() {
            let dirfd_path = read_dirfd_path(child, dirfd)?;
            path = dirfd_path.join(path);
        };
        Ok(path)
    }
}

pub(crate) fn get_exe(id: u32) -> Result<PathBuf, SyscallHandleError> {
    let path = PathBuf::from(format!("/proc/{id}/exe"));
    read_link(&path)
        .map_err(|source| SyscallHandleError::ReadLink { path, source })
}

fn read_abs_path(
    child: &mut Tracee,
    path_addr: u64,
) -> Result<PathBuf, SyscallHandleError> {
    let mut path = read_path(child, path_addr)?;
    if path.is_relative() {
        let dirfd_path = PathBuf::from(format!("/proc/{}/cwd", child.pid));
        let dirfd_path = read_link(&dirfd_path).map_err(|source| {
            SyscallHandleError::ReadLink {
                path: dirfd_path,
                source,
            }
        })?;
        path = dirfd_path.join(path);
    };
    Ok(path)
}

fn read_abs_path_from_dirfd(
    child: &mut Tracee,
    path_addr: u64,
    dirfd: i32,
) -> Result<PathBuf, SyscallHandleError> {
    let mut path = read_path(child, path_addr)?;
    if path.is_relative() {
        let dirfd_path = read_dirfd_path(child, dirfd)?;
        path = dirfd_path.join(path);
    };
    Ok(path)
}

fn read_dirfd_path(
    child: &mut Tracee,
    dirfd: i32,
) -> Result<PathBuf, SyscallHandleError> {
    let pid = child.pid;
    let dirfd_path = if dirfd == libc::AT_FDCWD {
        format!("/proc/{pid}/cwd")
    } else {
        format!("/proc/{pid}/fd/{dirfd}")
    };
    let dirfd_path = dirfd_path.into();
    read_link(&dirfd_path).map_err(|source| SyscallHandleError::ReadLink {
        path: dirfd_path,
        source,
    })
}

fn read_path(
    child: &mut Tracee,
    mut addr: u64,
) -> Result<PathBuf, SyscallHandleError> {
    const CHUNK_SIZE: usize = 128;
    let mut buf = vec![0; CHUNK_SIZE];
    let mut start = 0;
    loop {
        let read = child.read_memory_mut(addr, &mut buf[start..]).map_err(
            |source| SyscallHandleError::ReadChildMemory { addr, source },
        )?;
        let len = buf[start..start + read].iter().position(|&c| c == 0);
        if let Some(len) = len {
            buf.truncate(start + len);
            return Ok(OsString::from_vec(buf).into());
        }
        buf.resize(buf.len() + CHUNK_SIZE, 0);
        addr += CHUNK_SIZE as u64;
        start += CHUNK_SIZE;
    }
}
