//! lurk is a pretty (simple) alternative to strace.
//!
//! ## Installation
//!
//! Add the following dependencies to your `Cargo.toml`
//!
//! ```toml
//! [dependencies]
//! lurk-cli = "0.3.6"
//! nix = { version = "0.27.1", features = ["ptrace", "signal"] }
//! console = "0.15.8"
//! ```
//!
//! ## Usage
//!
//! First crate a tracee using [`run_tracee`] method. Then you can construct a [`Tracer`]
//! struct to trace the system calls via calling [`run_tracer`].
//!
//! ## Examples
//!
//! ```rust
//! use anyhow::{bail, Result};
//! use console::Style;
//! use lurk_cli::{args::Args, style::StyleConfig, Tracer};
//! use nix::unistd::{fork, ForkResult};
//! use std::io;
//!
//! fn main() -> Result<()> {
//!     let command = String::from("/usr/bin/ls");
//!
//!     let pid = match unsafe { fork() } {
//!         Ok(ForkResult::Child) => {
//!             return lurk_cli::run_tracee(&[command], &[], &None);
//!         }
//!         Ok(ForkResult::Parent { child }) => child,
//!         Err(err) => bail!("fork() failed: {err}"),
//!     };
//!
//!     let args = Args::default();
//!     let output = io::stdout();
//!     let style = StyleConfig {
//!         pid: Style::new().cyan(),
//!         syscall: Style::new().white().bold(),
//!         success: Style::new().green(),
//!         error: Style::new().red(),
//!         result: Style::new().yellow(),
//!         use_colors: true,
//!     };
//!
//!     Tracer::new(pid, args, output, style)?.run_tracer()
//! }
//! ```
//!
//! [`run_tracee`]: crate::run_tracee
//! [`Tracer`]: crate::Tracer
//! [`run_tracer`]: crate::Tracer::run_tracer

#[deny(clippy::pedantic, clippy::format_push_string)]
// TODO: re-check the casting lints - they might indicate an issue
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::redundant_closure_for_method_calls,
    clippy::struct_excessive_bools
)]
pub mod arch;
pub mod args;
pub mod style;
pub mod syscall_info;
pub mod message;

use anyhow::{anyhow, Result};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_BORDERS_ONLY;
use comfy_table::CellAlignment::Right;
use comfy_table::{Cell, ContentArrangement, Row, Table};
use libc::user_regs_struct;
use nix::sys::personality::{self, Persona};
use nix::sys::ptrace::{self, Event};
use nix::sys::signal::Signal;
use nix::sys::wait::{wait, WaitStatus};
use nix::unistd::Pid;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::{Duration, SystemTime};
use style::StyleConfig;
use syscalls::{Sysno, SysnoMap, SysnoSet};
use uzers::get_user_by_name;

use crate::args::Args;
use crate::arch::parse_args;
use crate::syscall_info::{RetCode, SyscallInfo};
use crate::message::Message;

const STRING_LIMIT: usize = 32;
const DELAY_MS: u64 = 200;

/*
As a teaching tool, it can be smart not to show every system calls
TODO : replace with a white list of syscalls
*/

const HIDDEN_SYSCALLS_LIST: [Sysno; 7] = [
    Sysno::arch_prctl,
    Sysno::set_tid_address,
    Sysno::set_robust_list,
    Sysno::rseq,
    Sysno::prlimit64,
    Sysno::mprotect,
    Sysno::getrandom,
];

pub struct Tracer<W: Write> {
    pid: Option<Pid>,
    args: Args,
    syscalls_time: SysnoMap<Duration>,
    syscalls_pass: SysnoMap<u64>,
    syscalls_fail: SysnoMap<u64>,
    style_config: StyleConfig,
    output: W,
    sender_to_gui: tokio::sync::mpsc::Sender<Message>,
    receiver_do_step: tokio::sync::mpsc::Receiver<()>,
    hidden_syscalls: HashSet<Sysno>,
    is_step_by_step: bool,
}

impl<W: Write> Tracer<W> {
    pub fn new(
        args: Args,
        output: W,
        style_config: StyleConfig,
        sender_to_gui: tokio::sync::mpsc::Sender<Message>,
        receiver_do_step: tokio::sync::mpsc::Receiver<()>,
    ) -> Result<Self> {
        Ok(Self {
            pid: None,
            args,
            syscalls_time: SysnoMap::from_iter(
                SysnoSet::all().iter().map(|v| (v, Duration::default())),
            ),
            syscalls_pass: SysnoMap::from_iter(SysnoSet::all().iter().map(|v| (v, 0))),
            syscalls_fail: SysnoMap::from_iter(SysnoSet::all().iter().map(|v| (v, 0))),
            style_config,
            output,
            sender_to_gui,
            receiver_do_step,
            hidden_syscalls: HashSet::from(HIDDEN_SYSCALLS_LIST),
            is_step_by_step: false,
        })
    }

    pub fn set_output(&mut self, output: W) {
        self.output = output;
    }

    #[allow(clippy::too_many_lines)]
    pub fn run_tracer(&mut self, pid: Pid) -> Result<()> {

        self.pid = Some(pid);

        // run the tracer whithout pause at the beginning
        self.is_step_by_step = false;

        // Create a hashmap to track entry and exit times across all forked processes individually.
        let mut start_times = HashMap::<Pid, Option<SystemTime>>::new();
        start_times.insert(pid, None);

        let mut options_initialized = false;
        /*
        let mut entry_regs = None;
        */

        loop {
            let status = wait()?;

            if !options_initialized {
                arch::ptrace_init_options_fork(pid)?;
                options_initialized = true;
            }

            match status {
                // `WIFSTOPPED(status), signal is WSTOPSIG(status)
                WaitStatus::Stopped(pid, signal) => {
                    // There are three reasons why a child might stop with SIGTRAP:
                    // 1) syscall entry
                    // 2) syscall exit
                    // 3) child calls exec
                    //
                    // Because we are tracing with PTRACE_O_TRACESYSGOOD, syscall entry and syscall exit
                    // are stopped in PtraceSyscall and not here, which means if we get a SIGTRAP here,
                    // it's because the child called exec.
                    if signal == Signal::SIGTRAP {
                        self.log_syscall_exit(pid);
                        /*
                        self.log_standard_syscall(pid, None, None, None)?;
                        */
                        self.issue_ptrace_syscall_request(pid, None)?;
                        continue;
                    }

                    // If we trace with PTRACE_O_TRACEFORK, PTRACE_O_TRACEVFORK, and PTRACE_O_TRACECLONE,
                    // a created child of our tracee will stop with SIGSTOP.
                    // If our tracee creates children of their own, we want to trace their syscall times with a new value.
                    if signal == Signal::SIGSTOP {
                        start_times.insert(pid, None);
                        // notify the GUI that the clone syscall returned 0
                        self.log_new_child(pid);
                        self.issue_ptrace_syscall_request(pid, None)?;
                        continue;
                    }

                    // The SIGCHLD signal is sent to a process when a child process terminates, interrupted, or resumes after being interrupted
                    // This means, that if our tracee forked and said fork exits before the parent, the parent will get stopped.
                    // Therefor issue a PTRACE_SYSCALL request to the parent to continue execution.
                    // This is also important if we trace without the following forks option.
                    if signal == Signal::SIGCHLD {
                        self.issue_ptrace_syscall_request(pid, Some(signal))?;
                        continue;
                    }

                    // If we fall through to here, we have another signal that's been sent to the tracee,
                    // in this case, just forward the singal to the tracee to let it handle it.
                    // TODO: Finer signal handling, edge-cases etc.
                    ptrace::cont(pid, signal)?;
                }
                // WIFEXITED(status)
                WaitStatus::Exited(pid, _) => {
                    continue;
                    /*
                    // If the process that exits is the original tracee, we can safely break here,
                    // but we need to continue if the process that exits is a child of the original tracee.
                    if self.pid.map_or(false, |p| p==pid) {
                        break;
                    } else {
                        continue;
                    };
                    */
                }
                // The traced process was stopped by a `PTRACE_EVENT_*` event.
                WaitStatus::PtraceEvent(pid, _, code) => {
                    // We stop at the PTRACE_EVENT_EXIT event because of the PTRACE_O_TRACEEXIT option.
                    // We do this to properly catch and log exit-family syscalls, which do not have an PTRACE_SYSCALL_INFO_EXIT event.
                    if code == Event::PTRACE_EVENT_EXIT as i32 && self.is_exit_syscall(pid)? {
                        self.log_syscall_exit(pid);
                        /*
                        self.log_standard_syscall(pid, None, None, None)?;
                        */
                    }

                    self.issue_ptrace_syscall_request(pid, None)?;
                }
                // Tracee is traced with the PTRACE_O_TRACESYSGOOD option.
                WaitStatus::PtraceSyscall(pid) => {
                    // ptrace(PTRACE_GETEVENTMSG,...) can be one of three values here:
                    // 1) PTRACE_SYSCALL_INFO_NONE
                    // 2) PTRACE_SYSCALL_INFO_ENTRY
                    // 3) PTRACE_SYSCALL_INFO_EXIT
                    let event = ptrace::getevent(pid)? as u8;

                    // Snapshot current time, to avoid polluting the syscall time with
                    // non-syscall related latency.
                    let timestamp = Some(SystemTime::now());

                    // We only want to log regular syscalls on exit
                    if let Some(syscall_start_time) = start_times.get_mut(&pid) {
                        if event == 2 {
                            /*
                            self.log_standard_syscall(
                                pid,
                                entry_regs,
                                *syscall_start_time,
                                timestamp,
                            )?;
                            */
                            self.log_syscall_exit(pid);
                            *syscall_start_time = None;
                        } else {
                            *syscall_start_time = timestamp;
                            /*
                            entry_regs = Some(self.get_registers(pid)?);
                            */

                            self.log_syscall_enter(pid);
                        }

                    } else {
                        return Err(anyhow!("Unable to get start time for tracee {}", pid));
                    }

                    self.issue_ptrace_syscall_request(pid, None)?;
                }
                // WIFSIGNALED(status), signal is WTERMSIG(status) and coredump is WCOREDUMP(status)
                WaitStatus::Signaled(pid, signal, coredump) => {
                    writeln!(
                        &mut self.output,
                        "Child {} terminated by signal {} {}",
                        pid,
                        signal,
                        if coredump { "(core dumped)" } else { "" }
                    )?;
                    self.log_process_termination(pid, signal);
                    break;
                }
                // WIFCONTINUED(status), this usually happens when a process receives a SIGCONT.
                // Just continue with the next iteration of the loop.
                WaitStatus::Continued(_) | WaitStatus::StillAlive => {
                    continue;
                }
            }
        }

        Ok(())
    }

    pub fn log_new_child(&mut self, pid: Pid) {
        self.sender_to_gui.blocking_send(Message::ReceivedSyscallExit(pid, Sysno::clone, RetCode::from_raw(0))).unwrap();
    }

    pub fn log_syscall_enter(&mut self, pid: Pid) {
        if let Ok((syscall_number, registers)) = self.parse_register_data(pid) {
            if self.args.raw || !self.hidden_syscalls.contains(&syscall_number) {

                if self.is_step_by_step == false && syscall_number == Sysno::write {
                    self.is_step_by_step = true;
                }

                let syscall_args = parse_args(pid, syscall_number, registers);

                let should_wait =
                    !self.args.raw &&
                    self.is_step_by_step &&
                    self.pid.map_or(false,|p| p == pid) &&
                    syscall_number != Sysno::wait4;

                self.sender_to_gui.blocking_send(Message::ReceivedSyscallEnter(pid, syscall_number, syscall_args, should_wait)).unwrap();

                if should_wait {
                    // waits for the user to complete this step
                    self.receiver_do_step.blocking_recv();
                } else {
                    std::thread::sleep(std::time::Duration::from_millis(DELAY_MS));
                }
            }
        }
    }

    pub fn log_syscall_exit(&mut self, pid: Pid) {
        if let Ok((syscall_number, registers)) = self.parse_register_data(pid) {
            // Theres no PTRACE_SYSCALL_INFO_EXIT for an exit-family syscall, hence ret_code will always be 0xffffffffffffffda (which is -38)
            // -38 is ENOSYS which is put into RAX as a default return value by the kernel's syscall entry code.
            // In order to not pollute the summary with this false positive, avoid exit-family syscalls from being counted (same behaviour as strace).
            let ret_code = match syscall_number {
                Sysno::exit | Sysno::exit_group => RetCode::from_raw(0),
                _ => {
                    #[cfg(target_arch = "x86_64")]
                    let code = RetCode::from_raw(registers.rax);
                    #[cfg(target_arch = "riscv64")]
                    let code = RetCode::from_raw(registers.a7);
                    #[cfg(target_arch = "aarch64")]
                    let code = RetCode::from_raw(registers.regs[0]);
                    match code {
                        RetCode::Err(_) => self.syscalls_fail[syscall_number] += 1,
                        _ => self.syscalls_pass[syscall_number] += 1,
                    }
                    code
                }
            };
            if self.args.raw || !self.hidden_syscalls.contains(&syscall_number) {
                self.sender_to_gui.blocking_send(Message::ReceivedSyscallExit(pid, syscall_number, ret_code)).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(DELAY_MS));
            }
        }
    }

    pub fn log_process_termination(&mut self, pid: Pid, signal: Signal) {
        self.sender_to_gui.blocking_send(Message::ReceivedProcessTermination(pid, signal)).unwrap();
    }

    // Issue a PTRACE_SYSCALL request to the tracee, forwarding a signal if one is provided.
    fn issue_ptrace_syscall_request(&self, pid: Pid, signal: Option<Signal>) -> Result<()> {
        ptrace::syscall(pid, signal)
            .map_err(|_| anyhow!("Unable to issue a PTRACE_SYSCALL request in tracee {}", pid))
    }

    // TODO: This is arch-specific code and should be modularized
    fn get_registers(&self, pid: Pid) -> Result<user_regs_struct> {
        ptrace::getregs(pid).map_err(|_| anyhow!("Unable to get registers from tracee {}", pid))
    }

    fn get_syscall(&self, registers: user_regs_struct) -> Result<Sysno> {
        #[cfg(target_arch = "x86_64")]
        let reg = registers.orig_rax;
        #[cfg(target_arch = "riscv64")]
        let reg = registers.a7;
        #[cfg(target_arch = "aarch64")]
        let reg = registers.regs[8];

        Ok(u32::try_from(reg)
            .map_err(|_| anyhow!("Invalid syscall number {reg}"))?
            .into())
    }

    // Issues a ptrace(PTRACE_GETREGS, ...) request and gets the corresponding syscall number (Sysno).
    fn parse_register_data(&self, pid: Pid) -> Result<(Sysno, user_regs_struct)> {
        let registers = self.get_registers(pid)?;
        let syscall_number = self.get_syscall(registers)?;

        Ok((syscall_number, registers))
    }

    fn is_exit_syscall(&self, pid: Pid) -> Result<bool> {
        self.get_registers(pid).map(|registers| {
            #[cfg(target_arch = "x86_64")]
            let reg = registers.orig_rax;
            #[cfg(target_arch = "riscv64")]
            let reg = registers.a7;
            #[cfg(target_arch = "aarch64")]
            let reg = registers.regs[8];
            reg == Sysno::exit as u64 || reg == Sysno::exit_group as u64
        })
    }
}

pub fn run_tracee(command: &[String], envs: &[String], username: &Option<String>) -> Result<()> {
    ptrace::traceme()?;
    personality::set(Persona::ADDR_NO_RANDOMIZE)
        .map_err(|_| anyhow!("Unable to set ADDR_NO_RANDOMIZE"))?;
    let mut binary = command
        .first()
        .ok_or_else(|| anyhow!("No command"))?
        .to_string();
    if let Ok(bin) = fs::canonicalize(&binary) {
        binary = bin
            .to_str()
            .ok_or_else(|| anyhow!("Invalid binary path"))?
            .to_string()
    }
    let mut cmd = Command::new(binary);
    cmd.args(command[1..].iter()); // .stdout(Stdio::null());

    for token in envs {
        let mut parts = token.splitn(2, '=');
        match (parts.next(), parts.next()) {
            (Some(key), Some(value)) => cmd.env(key, value),
            (Some(key), None) => cmd.env_remove(key),
            _ => unreachable!(),
        };
    }

    if let Some(username) = username {
        if let Some(user) = get_user_by_name(username) {
            cmd.uid(user.uid());
        }
    }

    let _ = cmd.exec();

    Ok(())
}
