use crate::syscall_info::{RetCode, SyscallArgs};
use nix::{sys::signal::Signal, unistd::Pid};
use syscalls::Sysno;

/// Messages handled by the GUI
#[derive(Debug, Clone)]
pub enum Message {
    /// User requested to start the tracer
    BtnStart,

    /// User requested to resume a specific process
    BtnContinue(Pid),

    /// The tracee started
    TraceeStarted(Pid),

    /// The tracee reached the post-exec ptrace stop
    TraceeFirstExec,

    /// The tracer is terminated
    TracerDone,

    /// A process is entering a syscall
    ReceivedSyscallEnter(u8, Pid, Sysno, SyscallArgs, bool),

    /// A process has completed a syscall
    ReceivedSyscallExit(u8, Pid, Sysno, RetCode, bool),

    /// A process is done
    ReceivedProcessTermination(Pid, Signal),
}
