mod timeline_entry;
mod tracer_manager;

use std::{collections::BTreeMap, os::unix::process};

use iced::{
    Alignment, Color, Element, Font, Length, Task,
    widget::{Row, button, column, container, row, rule, scrollable, text},
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
    pid_list: BTreeMap<Pid, ProcessState>,
    sender_do_start: std::sync::mpsc::Sender<()>,
    sender_do_step: std::sync::mpsc::Sender<Pid>,
}

struct ProcessState {
    last_timeline_index: Option<usize>,
    user_should_resume: bool,
    done: bool,
}

impl AppState {
    fn update(&mut self, message: Message) -> iced::Task<Message> {
        match message {
            Message::BtnStart => {
                self.state = RunningState::RunningBeforeFirstExec;
                self.timeline.clear();
                self.pid_list.clear();
                let _ = self.sender_do_start.send(());
                Task::none()
            }

            Message::TraceeProcessCreated(first_pid) => {
                // initial fork done, we know the tracee pid
                self.pid_list.insert(
                    first_pid,
                    ProcessState {
                        last_timeline_index: None,
                        user_should_resume: false,
                        done: false,
                    },
                );
                Task::none()
            }

            Message::TraceeFirstExec => {
                self.state = RunningState::Running;
                Task::none()
            }

            Message::ReceivedSyscallEnter(
                src_lineno,
                pid,
                syscall_number,
                syscall_args,
                paused,
            ) => {
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
                        "L{} L{} {}  {} ...",
                        src_lineno,
                        line!(),
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

                self.timeline.push(TimelineEntry::Syscall {
                    pid,
                    syscall_number,
                    args: Some(args),
                    ret_code: None,
                    log_text,
                });

                self.pid_list.entry(pid).and_modify(|entry| {
                    entry.last_timeline_index = Some(self.timeline.len() - 1);
                    entry.user_should_resume = paused;
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
                if (syscall_number == Sysno::clone) && (final_ret_code == RetCode::Ok(0)) {
                    // this is a new subprocess
                    let log_text = if cfg!(debug_assertions) {
                        format!("L{} L{} {}  … fork() → 0", src_lineno, line!(), pid,)
                    } else {
                        format!("{}  … fork() → 0", pid,)
                    };
                    self.timeline.push(TimelineEntry::Syscall {
                        pid,
                        syscall_number,
                        args: None,
                        ret_code: Some(final_ret_code),
                        log_text,
                    });
                    self.pid_list.insert(
                        pid,
                        ProcessState {
                            last_timeline_index: Some(self.timeline.len() - 1),
                            user_should_resume: should_pause,
                            done: false,
                        },
                    );
                    self.scroll_log_to_end()
                } else {
                    let str_ret_code = match final_ret_code {
                        RetCode::Ok(x) => format!("{}", x),
                        RetCode::Err(x) => format!("{}", x),
                        RetCode::Address(x) => format!("{}", x),
                    };

                    if let Some(index) = self
                        .pid_list
                        .get(&pid)
                        .and_then(|process_state| process_state.last_timeline_index)
                    {
                        let item = &mut self.timeline[index];
                        if let TimelineEntry::Syscall {
                            pid,
                            syscall_number,
                            args,
                            ret_code,
                            log_text,
                        } = item
                        {
                            *ret_code = Some(final_ret_code);

                            // Updating log text for the complete syscall
                            *log_text = if cfg!(debug_assertions) {
                                format!(
                                    "L{} L{} {}  {} → {}",
                                    src_lineno,
                                    line!(),
                                    pid,
                                    fmt_syscall_name(
                                        *syscall_number,
                                        &args.as_ref().unwrap().join(",")
                                    ),
                                    str_ret_code
                                )
                            } else {
                                format!(
                                    "{}  {} → {}",
                                    pid,
                                    fmt_syscall_name(
                                        *syscall_number,
                                        &args.as_ref().unwrap().join(",")
                                    ),
                                    str_ret_code
                                )
                            };
                        };
                        if let Some(process_state) = self.pid_list.get_mut(&pid) {
                            if syscall_number == Sysno::exit_group {
                                process_state.last_timeline_index = None;
                                process_state.done = true;
                            }
                            process_state.user_should_resume = should_pause;
                        }
                    }
                    Task::none()
                }
            }

            Message::ReceivedProcessTermination(pid, signal) => {
                let log_text = format!("{}  received signal {}", pid, signal);
                self.timeline.push(TimelineEntry::Signal {
                    pid,
                    signal,
                    log_text,
                });
                if let Some(process_state) = self.pid_list.get_mut(&pid) {
                    process_state.done = true;
                }
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
            let first_pid = self.pid_list.first_key_value().map(|(k, _)| *k);

            let t = self.timeline.iter().enumerate().map(|(i, entry)| {
                let pid = entry.get_pid();
                let user_should_resume = self
                    .pid_list
                    .get(&pid)
                    .map(|x| x.user_should_resume)
                    .unwrap_or_default();
                let is_last_entry = self
                    .pid_list
                    .get(&pid)
                    .map(|x| x.last_timeline_index)
                    .flatten()
                    == Some(i);
                entry.view(Some(pid) == first_pid, is_last_entry, user_should_resume)
            });

            scrollable(column(t).spacing(2))
                .height(Length::Fill)
                .width(Length::Fill)
                .id("log")
        };

        let processes_view = {
            let font = Font { ..Font::MONOSPACE };

            let t = self.pid_list.iter().map(|(pid, process_state)| {
                let content = if !process_state.done {
                    format!("  {pid}")
                } else {
                    format!("✘ {pid}")
                };
                let t = text(content).font(font); //.into()
                if process_state.user_should_resume {
                    row![t, button("▶️").on_press(Message::BtnContinue(*pid)),]
                        .align_y(Alignment::Center)
                        .into()
                } else {
                    t.into()
                }
            });
            let scroll = scrollable(column(t).spacing(2))
                .height(Length::Fill)
                .width(Length::Fixed(200.0))
                .id("process");

            container(scroll).style(|_theme| container::Style {
                background: Some(Color::from_rgb8(240, 240, 240).into()),
                ..Default::default()
            })
        };

        column![
            top_row,
            rule::horizontal(5),
            row![timeline_view, processes_view]
        ]
        .into()
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
