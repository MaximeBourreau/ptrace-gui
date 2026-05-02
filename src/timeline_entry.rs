use iced::{
    Alignment, Font, color,
    widget::{button, row, text},
};
use nix::unistd::Pid;
use ptrace_gui::{message::Message, syscall_info::RetCode};
use syscalls::Sysno;

pub enum TimelineEntry {
    Syscall {
        pid: Pid,
        syscall_number: Sysno,
        args: Option<Vec<String>>,
        ret_code: Option<RetCode>,
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
        // Extract the pid and the string of this log item
        match self {
            TimelineEntry::Syscall { pid, .. } => *pid,
            TimelineEntry::Signal { pid, .. } => *pid,
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
