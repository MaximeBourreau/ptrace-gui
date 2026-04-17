use iced::{
    Alignment, Font, color,
    widget::{button, row, text},
};
use nix::unistd::Pid;
use ptrace_gui::{message::Message, syscall_info::RetCode};
use syscalls::Sysno;

pub enum LogItem {
    Syscall {
        pid: Pid,
        syscall_number: Sysno,
        paused: bool,
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

impl LogItem {
    pub fn view(&self, first_pid: Option<Pid>) -> iced::Element<Message> {
        let font = Font {
            weight: iced::font::Weight::Bold,
            ..Font::MONOSPACE
        };
        // Extract the pid and the string of this log item
        let (pid, log_text, paused) = match self {
            LogItem::Syscall {
                pid,
                log_text,
                paused,
                ..
            } => (pid, log_text, *paused),
            LogItem::Signal { pid, log_text, .. } => (pid, log_text, false),
        };
        // Display first process and its child processes in different colors
        let c = if first_pid == Some(*pid) {
            color!(0x2d6a9f)
        } else {
            color!(0x3e8e3e)
        };
        let t = text(log_text).color(c).font(font);
        if paused {
            row![t, button("▶️").on_press(Message::BtnContinue(*pid)),]
                .align_y(Alignment::Center)
                .into()
        } else {
            t.into()
        }
    }
}
