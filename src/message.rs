use crate::syscall_info::{RetCode, SyscallArgs};
use nix::sys::signal::Signal;
use syscalls::Sysno;

#[derive(Debug, Clone)]
pub enum Message {
    // user messages
    BtnStart,
    BtnContinue,
    // manage_processes_loop messages
    TraceeStarted(i32),
    TracerDone,
    // tracer messages
    ReceivedSyscallEnter(i32, Sysno, SyscallArgs, bool),
    ReceivedSyscallExit(i32, Sysno, RetCode), // TODO : add Duration
    ReceivedProcessTermination(i32, Signal),
}
