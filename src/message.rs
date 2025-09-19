use nix::{
    unistd::Pid,
    sys::signal::Signal,
};
use syscalls::Sysno;
use crate::syscall_info::{
    RetCode,
    SyscallArgs,
};

#[derive(Debug, Clone)]
pub enum Message {
    BtnStart,
    ReceivedSyscallEnter(Pid, Sysno, SyscallArgs, bool),
    ReceivedSyscallExit(Pid, Sysno, RetCode), // TODO : add Duration
    ReceivedProcessTermination(Pid, Signal),
    BtnContinue,
    TracerDone,
}
