use crate::syscall_info::{RetCode, SyscallArgs};
use nix::{
    sys::signal::Signal,
    unistd::Pid,
};
use syscalls::Sysno;

#[derive(Debug, Clone)]
pub enum TracerEvent {
    SyscallEnter(Pid, Sysno, SyscallArgs),
    SyscallExit(Pid, Sysno, RetCode), // TODO : add Duration
    Termination(Pid, Signal),
}
