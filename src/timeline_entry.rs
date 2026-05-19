use iced::{
    Alignment, Font, color,
    widget::{button, row, text},
};
use nix::{sys::signal::Signal, unistd::Pid};
use ptrace_gui::{
    message::Message,
    syscall_info::{RetCode, SyscallArgs},
};
use syscalls::Sysno;

pub enum TimelineEntry {
    Syscall {
        pid: Pid,
        syscall_number: Sysno,
        syscall_args: Option<SyscallArgs>,
        ret_code: Option<RetCode>,
        last_src_lineno: u32,
        log_text: String,
    },
    Signal {
        pid: Pid,
        signal: nix::sys::signal::Signal,
        log_text: String,
    },
}

impl TimelineEntry {
    pub fn get_pid(&self) -> Pid {
        // Extract the pid of this log item
        match self {
            TimelineEntry::Syscall { pid, .. } => *pid,
            TimelineEntry::Signal { pid, .. } => *pid,
        }
    }

    pub fn syscall_enter(
        pid: Pid,
        syscall_number: Sysno,
        syscall_args: SyscallArgs,
        src_lineno: u32,
    ) -> Self {



        // Preparing log text for a syscall start
        let log_text = if cfg!(debug_assertions) {
            format!(
                "L{} {}  {} ...",
                src_lineno,
                pid,
                Self::fmt_syscall_name(syscall_number, Some(&syscall_args))
            )
        } else {
            format!(
                "{}  {} ...",
                pid,
                Self::fmt_syscall_name(syscall_number, Some(&syscall_args))
            )
        };

        TimelineEntry::Syscall {
            pid,
            syscall_number,
            syscall_args: Some(syscall_args),
            ret_code: None,
            last_src_lineno: src_lineno,
            log_text,
        }
    }

    pub fn syscall_exit(&mut self, final_ret_code: RetCode, src_lineno: u32) {
        let str_ret_code = match final_ret_code {
            RetCode::Ok(x) => format!("{}", x),
            RetCode::Err(x) => format!("{}", x),
            RetCode::Address(x) => format!("{}", x),
        };

        if let TimelineEntry::Syscall {
            pid,
            syscall_number,
            syscall_args,
            ret_code,
            log_text,
            last_src_lineno,
        } = self
        {

            *ret_code = Some(final_ret_code);
            *last_src_lineno = src_lineno;

            // Updating log text for the complete syscall
            *log_text = if cfg!(debug_assertions) {
                format!(
                    "L{} {}  {} → {}",
                    src_lineno,
                    pid,
                    Self::fmt_syscall_name(*syscall_number, syscall_args.as_ref()),
                    str_ret_code
                )
            } else {
                format!(
                    "{}  {} → {}",
                    pid,
                    Self::fmt_syscall_name(*syscall_number, syscall_args.as_ref()),
                    str_ret_code
                )
            };
        };
    }

    fn fmt_syscall_name(syscall_number: Sysno, syscall_args: Option<&SyscallArgs>) -> String {
        match syscall_number {
            Sysno::clone => "fork()".to_string(),
            Sysno::wait4 => "waitpid(…)".to_string(),
            Sysno::exit_group => format!("exit({})", syscall_args.map_or(String::new(), |a| a.to_string())),
            _ => format!("{}({})", syscall_number, syscall_args.map_or(String::new(), |a| a.to_string())),
        }
    }

    pub fn new_subprocess(
        pid: Pid,
        syscall_number: Sysno,
        final_ret_code: RetCode,
        src_lineno: u32,
    ) -> Self {
        let log_text = if cfg!(debug_assertions) {
            format!("L{} {}  … fork() → 0", src_lineno, pid)
        } else {
            format!("{}  … fork() → 0", pid)
        };
        TimelineEntry::Syscall {
            pid,
            syscall_number,
            syscall_args: None,
            ret_code: Some(final_ret_code),
            log_text,
            last_src_lineno: src_lineno,
        }
    }

    pub fn new_signal(pid: Pid, signal: Signal) -> TimelineEntry {
        let log_text = format!("{} received signal {}", pid, signal);
        TimelineEntry::Signal {
            pid,
            signal,
            log_text,
        }
    }

    pub fn view(
        &self,
        is_first_pid: bool,
        is_last_entry: bool,
        user_should_resume: bool,
    ) -> iced::Element<Message> {
        let font = Font {
            weight: iced::font::Weight::Bold,
            ..Font::MONOSPACE
        };
        // Extract the pid and the string of this log item
        let (pid, log_text) = match self {
            TimelineEntry::Syscall { pid, log_text, .. } => (pid, log_text),
            TimelineEntry::Signal { pid, log_text, .. } => (pid, log_text),
        };
        // Display first process and its child processes in different colors
        let c = if is_first_pid {
            color!(0x2d6a9f)
        } else {
            color!(0x3e8e3e)
        };
        let t = text(log_text).color(c).font(font);
        if user_should_resume && is_last_entry {
            row![t, button("▶️").on_press(Message::BtnContinue(*pid)),]
                .align_y(Alignment::Center)
                .into()
        } else {
            t.into()
        }
    }
}
