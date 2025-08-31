use crate::SyscallInfo;
use nix::{
    sys::signal::Signal,
    unistd::Pid,
};

#[derive(Debug, Clone)]
pub enum TracerEvent {
    Syscall(SyscallInfo),
    Termination(Pid, Signal),
}
