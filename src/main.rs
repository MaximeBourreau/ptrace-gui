mod manage_processes_loop;

use manage_processes_loop::manage_processes_loop;

use ptrace_gui::{
    message::Message,
    syscall_info::{
        RetCode,
        SyscallArg,
    },
};
use syscalls::Sysno;
use iced::{
    Element,
    Font,
    Length::Fill,
    Task,
    color,
    widget::{
        Row,
        button,
        column,
        rule,
        scrollable,
        space,
        text,
    },
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

const INITIAL_WIDTH: f32 = 800.0;
const INITIAL_HEIGHT: f32 = 480.0;

fn main() {
    let _ = iced::application(
        || {
            let (sender_do_start, sender_do_step, receiver_to_gui) = manage_processes_loop();
            (
                AppGui {
                    log: Vec::new(),
                    state: RunningState::NeverStarted,
                    is_paused: false,
                    pid: None,
                    sender_do_start,
                    sender_do_step,
                },
                Task::stream(ReceiverStream::new(receiver_to_gui))
            )
        },
        AppGui::update,
        AppGui::view
    )
    .window_size((INITIAL_WIDTH, INITIAL_HEIGHT))
    .run();
}

#[derive(PartialEq)]
enum RunningState {
    NeverStarted,
    RunningWithoutFirstExec,
    Running,
    DoneWithoutFirstExec,
    Done,
}

enum LogItem {
    Syscall { pid: i32, syscall_number: Sysno, args: Option<Vec<String>>, ret_code: Option<RetCode>, log_text: String },
    Signal { pid: i32, signal: nix::sys::signal::Signal, log_text: String },
}

struct AppGui {
    log: Vec<LogItem>,
    state: RunningState,
    is_paused: bool,
    pid: Option<i32>,
    sender_do_start: mpsc::Sender<()>,
    sender_do_step: mpsc::Sender<()>,
}

impl AppGui {

    fn update(&mut self, message: Message) -> iced::Task<Message> {
        match message {

            Message::BtnStart => {
                self.state = RunningState::RunningWithoutFirstExec;
                self.log.clear();
                let _ = self.sender_do_start.try_send(());
                Task::none()
            }

            Message::TraceeStarted(pid) => {
                self.pid = Some(pid);
                Task::none()
            }

            Message::ReceivedSyscallEnter(pid, syscall_number, syscall_args, should_pause) => {

                self.is_paused = should_pause;

                let args: Vec<String> = syscall_args.0
                    .iter()
                    .map(|arg| {
                        match arg {
                            SyscallArg::Int(v) => format!("{}", *v), // TODO hex and bit representation
                            SyscallArg::Str(v) => format!("{:?}", v),
                            SyscallArg::Addr(v) => {
                                if *v == 0 {
                                    String::from("NULL")
                                } else {
                                    String::from("…")
                                }
                            },
                        }
                    })
                    .collect();

                // Preparing log text for a syscall start
                // TODO : improve
                let log_text = if syscall_number == Sysno::clone {
                    format!(
                        "{}  fork() ...⏸️",
                        pid,
                    )
                } else {
                    format!(
                        "{}  {}({}) ...⏸️",
                        pid,
                        syscall_number,
                        args.join(",")
                    )
                };

                self.log.push(LogItem::Syscall { pid, syscall_number, args: Some(args), ret_code: None, log_text });
                self.scroll_log_to_end()
            }

            Message::ReceivedSyscallExit(pid, syscall_number, final_ret_code) => {

                let str_ret_code = match final_ret_code {
                    RetCode::Ok(x) => format!("{}", x),
                    RetCode::Err(x) => format!("{}", x),
                    RetCode::Address(x) => format!("{}", x),
                };

                // check if this syscall is exec
                if self.state == RunningState::RunningWithoutFirstExec && syscall_number == Sysno::execve {
                    self.state = RunningState::Running;
                }

                if let Some(index) = self.find_syscall_item(pid, syscall_number) {
                    let item = &mut self.log[index];
                    if let LogItem::Syscall { pid , syscall_number, args, ret_code, log_text } = item {
                        *ret_code = Some(final_ret_code);
                        // Updating log text for the complete syscall
                        // TODO : improve
                        *log_text = if *syscall_number == Sysno::clone {
                            format!(
                                "{}  fork() → {}",
                                pid,
                                str_ret_code
                            )
                        } else {
                            format!(
                                "{}  {}({}) → {}",
                                pid,
                                syscall_number,
                                args.as_ref().unwrap().join(","),
                                str_ret_code
                            )
                        };
                    };
                    Task::none()
                } else {
                    // Preparing log text for a syscall return
                    // TODO : improve
                    let log_text = if syscall_number == Sysno::clone {
                        format!(
                            "{}  … fork()  → {}",
                            pid,
                            str_ret_code
                        )
                    } else {
                        format!(
                            "{}  … {}(…) → {}",
                            pid,
                            syscall_number,
                            str_ret_code,
                        )
                    };

                    self.log.push(LogItem::Syscall { pid, syscall_number, args: None, ret_code: Some(final_ret_code), log_text });
                    self.scroll_log_to_end()
                }
            }

            Message::ReceivedProcessTermination(pid, signal) => {
                let log_text = format!(
                    "{}  received signal {}",
                    pid,
                    signal
                );
                self.log.push(LogItem::Signal { pid, signal, log_text });
                self.scroll_log_to_end()
            }

            Message::BtnContinue => {
                self.is_paused = false;
                let _ = self.sender_do_step.try_send(());
                Task::none()
            }

            Message::TracerDone => {
                self.state = if self.state == RunningState::RunningWithoutFirstExec {
                    RunningState::DoneWithoutFirstExec
                } else {
                    RunningState::Done
                };
                Task::none()
            }

        }
    }

    /*
    Search the last syscall item, matching pid and syscall number, in the log
     */
    fn find_syscall_item(&mut self, searched_pid: i32, searched_syscall_number: Sysno) -> Option<usize> {
        self.log.iter().rposition(|item| {
            match item {
                LogItem::Syscall { pid, syscall_number, .. } => {
                  searched_pid == *pid && searched_syscall_number == *syscall_number  
                },
                _ => false
            }
        })
    }

    fn scroll_log_to_end(&mut self) -> iced::Task<Message> {
        iced::widget::operation::snap_to(
            "log",
            scrollable::RelativeOffset::END
        )
    }

    fn view(&self) -> Element<Message> {

        let top_row = {

            let execution_status = match self.state {
                RunningState::Running | RunningState::RunningWithoutFirstExec => Some(text("Running")),
                RunningState::Done => Some(text("Terminated")),
                RunningState::DoneWithoutFirstExec => Some(text("Execution of the traced program failed")),
                _ => None,
            };

            let btn_start = match self.state {
                RunningState::NeverStarted => Some(button("start").on_press(Message::BtnStart)),
                RunningState::Done | RunningState::DoneWithoutFirstExec => Some(button("restart").on_press(Message::BtnStart)),
                _ => None
            };

            let btn_paused = match self.state {
                RunningState::Running | RunningState::RunningWithoutFirstExec => if self.is_paused {
                    Some(button("continue").on_press(Message::BtnContinue))
                } else {
                    Some(button("continue"))
                }
                _ => None,
            };

            Row::new()
                .align_y(iced::Center)
                .padding(5)
                .spacing(5)
                .push(execution_status)
                .push(btn_start)
                .push(space::horizontal())
                .push(btn_paused)
        };

        let tracer_log: Element<_> = {
            let t = self.log.iter().map(|log_item| {
                let font = Font { weight: iced::font::Weight::Bold, ..Font::MONOSPACE};
                // Extract the pid and the string of this log item
                let (pid, log_text) = match log_item {
                    LogItem::Syscall { pid, syscall_number: _, args: _, ret_code: _, log_text } => (pid, log_text),
                    LogItem::Signal { pid, signal: _, log_text } => (pid, log_text),
                };
                // Display first process and its child processes in different colors
                let c = if *pid == self.pid.unwrap_or(-1) {
                    // color!(0x428BCA)
                    color!(0x2d6a9f)
                } else {
                    // color!(0x5CB85C)
                    color!(0x3e8e3e)
                };
                Element::from(
                    text(log_text)
                        .color(c)
                        .font(font)
                )
            });

            scrollable(column(t).spacing(2))
                .height(Fill)
                .width(Fill)
                .id("log")
                .into()
        };

        column![
            top_row,
            rule::horizontal(5),
            tracer_log,
        ].into()
    }
}
