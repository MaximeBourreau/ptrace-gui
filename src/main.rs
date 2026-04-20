mod timeline_entry;
mod tracer_manager;

use std::collections::BTreeMap;

use iced::{
    Element, Length, Task,
    widget::{Row, button, column, rule, scrollable, text},
};
use nix::unistd::Pid;
use ptrace_gui::{
    message::Message,
    syscall_info::{RetCode, SyscallArg},
};
use syscalls::Sysno;
use tokio_stream::wrappers::ReceiverStream;

use crate::timeline_entry::TimelineEntry;

const INITIAL_WIDTH: f32 = 800.0;
const INITIAL_HEIGHT: f32 = 480.0;

fn main() {
    let _ = iced::application(
        || {
            let (sender_do_start, sender_do_step, receiver_to_gui) = tracer_manager::run();
            (
                AppState {
                    timeline: Vec::new(),
                    state: RunningState::NeverStarted,
                    first_pid: None,
                    pid_list: BTreeMap::new(),
                    sender_do_start,
                    sender_do_step,
                },
                Task::stream(ReceiverStream::new(receiver_to_gui)),
            )
        },
        AppState::update,
        AppState::view,
    )
    .window_size((INITIAL_WIDTH, INITIAL_HEIGHT))
    .run();
}

#[derive(PartialEq)]
enum RunningState {
    NeverStarted,
    RunningBeforeFirstExec,
    Running,
    DoneWithoutFirstExec,
    Done,
}

struct AppState {
    timeline: Vec<TimelineEntry>,
    state: RunningState,
    first_pid: Option<Pid>, // TODO: remove (redundant with the first entry of pid_list, when not empty; should use pid_list.first_key_value())
    pid_list: BTreeMap<Pid, ProcessState>,
    sender_do_start: std::sync::mpsc::Sender<()>,
    sender_do_step: std::sync::mpsc::Sender<Pid>,
}

struct ProcessState;

impl AppState {
    fn update(&mut self, message: Message) -> iced::Task<Message> {
        match message {
            Message::BtnStart => {
                self.state = RunningState::RunningBeforeFirstExec;
                self.timeline.clear();
                self.first_pid.take();
                self.pid_list.clear();
                let _ = self.sender_do_start.send(());
                Task::none()
            }

            Message::TraceeStarted(first_pid) => {
                self.first_pid = Some(first_pid);
                Task::none()
            }

            Message::TraceeFirstExec => {
                self.state = RunningState::Running;
                Task::none()
            }

            Message::ReceivedSyscallEnter(src_lineno, pid, syscall_number, syscall_args, paused) => {
                self.pid_list.insert(pid, ProcessState);

                let args: Vec<String> = syscall_args
                    .0
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
                            }
                        }
                    })
                    .collect();

                // Preparing log text for a syscall start
                let log_text = if cfg!(debug_assertions) {
                    format!(
                        "L{} {}  {} ...",
                        src_lineno,
                        pid,
                        fmt_syscall_name(syscall_number, &args.join(","))
                    )
                } else {
                    format!(
                        "{}  {} ...",
                        pid,
                        fmt_syscall_name(syscall_number, &args.join(","))
                    )
                };

                if let Some(item) = self.timeline.iter_mut().rfind(|item| {
                    if let TimelineEntry::Syscall {
                        pid: search_pid, ..
                    } = item
                    {
                        *search_pid == pid
                    } else {
                        false
                    }
                }) {
                    if let TimelineEntry::Syscall { paused, .. } = item {
                        *paused = false;
                    }
                }

                self.timeline.push(TimelineEntry::Syscall {
                    pid,
                    syscall_number,
                    paused,
                    args: Some(args),
                    ret_code: None,
                    log_text,
                });
                self.scroll_log_to_end()
            }

            Message::ReceivedSyscallExit(
                src_lineno,
                pid,
                syscall_number,
                final_ret_code,
                should_pause,
            ) => {
                let str_ret_code = match final_ret_code {
                    RetCode::Ok(x) => format!("{}", x),
                    RetCode::Err(x) => format!("{}", x),
                    RetCode::Address(x) => format!("{}", x),
                };

                if let Some(index) = self.find_syscall_item(pid, syscall_number) {
                    let item = &mut self.timeline[index];
                    if let TimelineEntry::Syscall {
                        pid,
                        syscall_number,
                        paused,
                        args,
                        ret_code,
                        log_text,
                    } = item
                    {
                        *ret_code = Some(final_ret_code);

                        // Updating log text for the complete syscall
                        *log_text = if cfg!(debug_assertions) {
                            format!(
                                "L{} {}  {} → {}",
                                src_lineno,
                                pid,
                                fmt_syscall_name(*syscall_number, &args.as_ref().unwrap().join(",")),
                                str_ret_code
                            )
                        } else {
                            format!(
                                "{}  {} → {}",
                                pid,
                                fmt_syscall_name(*syscall_number, &args.as_ref().unwrap().join(",")),
                                str_ret_code
                            )
                        };

                        *paused = should_pause;
                    };
                    Task::none()
                } else {
                    if syscall_number == Sysno::clone {
                        self.pid_list.insert(pid, ProcessState);
                    }
                    // Preparing log text for a syscall return
                    let log_text = if cfg!(debug_assertions) {
                        format!(
                            "L{} {}  … {} → {}",
                            src_lineno,
                            pid,
                            fmt_syscall_name(syscall_number, "…"),
                            str_ret_code
                        )
                    } else {
                        format!(
                            "{}  … {} → {}",
                            pid,
                            fmt_syscall_name(syscall_number, "…"),
                            str_ret_code
                        )
                    };

                    self.timeline.push(TimelineEntry::Syscall {
                        pid,
                        syscall_number,
                        paused: should_pause,
                        args: None,
                        ret_code: Some(final_ret_code),
                        log_text,
                    });
                    self.scroll_log_to_end()
                }
            }

            Message::ReceivedProcessTermination(pid, signal) => {
                let log_text = format!("{}  received signal {}", pid, signal);
                self.timeline.push(TimelineEntry::Signal {
                    pid,
                    signal,
                    log_text,
                });
                self.scroll_log_to_end()
            }

            Message::BtnContinue(pid) => {
                let _ = self.sender_do_step.send(pid);
                Task::none()
            }

            Message::TracerDone => {
                self.state = if self.state == RunningState::RunningBeforeFirstExec {
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
    fn find_syscall_item(
        &mut self,
        searched_pid: Pid,
        searched_syscall_number: Sysno,
    ) -> Option<usize> {
        self.timeline.iter().rposition(|item| match item {
            TimelineEntry::Syscall {
                pid,
                syscall_number,
                ..
            } => searched_pid == *pid && searched_syscall_number == *syscall_number,
            _ => false,
        })
    }

    fn scroll_log_to_end(&mut self) -> iced::Task<Message> {
        iced::widget::operation::snap_to("log", scrollable::RelativeOffset::END)
    }

    fn view(&self) -> Element<Message> {
        let execution_status = match self.state {
            RunningState::Running | RunningState::RunningBeforeFirstExec => Some(text("Running")),
            RunningState::Done => Some(text("Terminated")),
            RunningState::DoneWithoutFirstExec => {
                Some(text("Execution of the traced program failed"))
            }
            _ => None,
        };

        let btn_start = match self.state {
            RunningState::NeverStarted => Some(button("start").on_press(Message::BtnStart)),
            RunningState::Done | RunningState::DoneWithoutFirstExec => {
                Some(button("restart").on_press(Message::BtnStart))
            }
            _ => None,
        };

        let top_row = Row::from_vec(vec![execution_status.into(), btn_start.into()])
            .align_y(iced::Center)
            .padding(5)
            .spacing(5);

        let timeline_view = {
            let t = self
                .timeline
                .iter()
                .map(|log_item| log_item.view(self.first_pid));

            scrollable(column(t).spacing(2))
                .height(Length::Fill)
                .width(Length::Fill)
                .id("log")
        };

        column![top_row, rule::horizontal(5), timeline_view].into()
    }
}

fn fmt_syscall_name(syscall_number: Sysno, args: &str) -> String {
    match syscall_number {
        Sysno::clone => "fork()".to_string(),
        Sysno::wait4 => "waitpid(…)".to_string(),
        Sysno::exit_group => format!("exit({})", args),
        _ => format!("{}({})", syscall_number, args),
    }
}
