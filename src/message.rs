use crate::syscall_info::{RetCode, SyscallArgs};
use nix::{sys::signal::Signal, unistd::Pid};
use syscalls::Sysno;

#[derive(Debug, Clone)]
pub enum Message {
    // user messages
    BtnStart,
    BtnContinue,
    // manage_processes_loop messages
    TraceeStarted(Pid),
    TracerDone,
    // tracer messages
    ReceivedSyscallEnter(Pid, Sysno, SyscallArgs, bool),
    ReceivedSyscallExit(Pid, Sysno, RetCode),
    ReceivedProcessTermination(Pid, Signal),
}
