use console::Style;
use ptrace_gui::{
    args::Args,
    message::Message,
    run_tracee,
    style::StyleConfig,
    syscall_info::{
        RetCode,
        SyscallArg,
    },
    Tracer,
};
use nix::unistd::{
    fork,
    ForkResult,
};
use std::{
    cell::RefCell,
    io,
    rc::Rc,
};
use syscalls::Sysno;
use iced::{
    color,
    widget::{
        button,
        column,
        horizontal_rule,
        horizontal_space,
        Row,
        scrollable,
        text,
    },
    Element,
    Font,
    Length::Fill,
    Task,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

const INITIAL_WIDTH: f32 = 800.0;
const INITIAL_HEIGHT: f32 = 480.0;

fn main() {

    let (sender_to_gui, receiver_to_gui) = mpsc::channel::<Message>(1000);

    let (sender_do_start, mut receiver_do_start) = mpsc::channel::<()>(1);
    let (sender_do_step, receiver_do_step) = mpsc::channel::<()>(1);

    std::thread::spawn(move || {

        let mut args = Args::default();
        args.follow_forks = true;

        let output = io::stdout();
        let style = StyleConfig {
            pid: Style::new().cyan(),
            syscall: Style::new().white().bold(),
            success: Style::new().green(),
            error: Style::new().red(),
            result: Style::new().yellow(),
            use_colors: true,
        };

        let mut tracer = {
            let sender_to_gui = sender_to_gui.clone();

            Tracer::new(
                args,
                output,
                style,
                sender_to_gui,
                receiver_do_step,
            ).unwrap()
        };

        let command = std::env::args().nth(1).unwrap();

        // the tracer (and the traced program) can be executed multiple times with this loop

        loop {

            // waiting for the user action to start (or restart) the tracer
            if receiver_do_start.blocking_recv().is_none() {
                break;
            }

            // run the traced program

            let pid = match unsafe { fork() } {
                Ok(ForkResult::Child) => {
                    let _ = run_tracee(&[command], &[], &None);
                    break;
                },
                Ok(ForkResult::Parent { child }) => {
                    child
                },
                Err(err) => {
                    eprintln!("fork() failed: {err}");
                    std::process::exit(-1);
                }
            };

            // run the tracer

            let _ = tracer.run_tracer(pid);

            // tell the user the tracer (and the traced program) has terminated

            sender_to_gui.blocking_send(Message::TracerDone).unwrap();

        }
    });

    let _ = iced::application("ptrace-gui", AppGui::update, AppGui::view)
        .window_size((INITIAL_WIDTH, INITIAL_HEIGHT))
        .run_with(move || AppGui::new(receiver_to_gui, sender_do_start, sender_do_step));
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
    Syscall { pid: i32, syscall_number: Sysno, args: Option<Vec<String>>, ret_code: Option<RetCode>, s: String },
    Signal { pid: i32, signal: nix::sys::signal::Signal, s: String },
}

struct AppGui {
    log: Vec<LogItem>,
    state: RunningState,
    is_paused: bool,
    sender_do_start: mpsc::Sender<()>,
    sender_do_step: mpsc::Sender<()>,
}

impl AppGui {
    fn new(
        receiver_to_gui: mpsc::Receiver<Message>,
        sender_do_start: mpsc::Sender<()>,
        sender_do_step: mpsc::Sender<()>,
    ) -> (Self, Task<Message>) {

        (
            Self {
                log: Vec::new(),
                state: RunningState::NeverStarted,
                is_paused: false,
                sender_do_start,
                sender_do_step,
            },

            Task::stream(ReceiverStream::new(receiver_to_gui)),
        )
    }

    fn update(&mut self, message: Message) -> iced::Task<Message> {
        match message {

            Message::BtnStart => {
                self.state = RunningState::RunningWithoutFirstExec;
                self.log.clear();
                let _ = self.sender_do_start.try_send(());
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

                let s = format!("{} {}({}) …", pid.as_raw(), syscall_number, args.join(","));

                self.log.push(LogItem::Syscall { pid: pid.as_raw(), syscall_number, args: Some(args), ret_code: None, s });
                self.scroll_log_to_end()
            }

            Message::ReceivedSyscallExit(pid, syscall_number, final_ret_code) => {

                // check if this syscall is exec
                if self.state == RunningState::RunningWithoutFirstExec && syscall_number == Sysno::execve {
                    self.state = RunningState::Running;
                }

                if let Some(index) = self.find_syscall_item(pid.as_raw(), syscall_number) {
                    let item = &mut self.log[index];
                    if let LogItem::Syscall { pid , syscall_number, args, ret_code, s } = item {
                        *ret_code = Some(final_ret_code);
                        *s = format!(
                            "{} {}({}) -> {}",
                            pid,
                            syscall_number,
                            args.as_ref().unwrap().join(","),
                            final_ret_code
                        );
                    };
                    Task::none()
                } else {
                    let s = format!(
                        "{} … {} → {}",
                        pid.as_raw(),
                        syscall_number,
                        final_ret_code,
                    );

                    self.log.push(LogItem::Syscall { pid: pid.as_raw(), syscall_number, args: None, ret_code: Some(final_ret_code), s });
                    self.scroll_log_to_end()
                }
            }

            Message::ReceivedProcessTermination(pid, signal) => {
                let s = format!("{} received signal {}", pid.as_raw(), signal);
                self.log.push(LogItem::Signal { pid: pid.as_raw(), signal, s });
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
                LogItem::Syscall { pid, syscall_number, args: _, ret_code: _, s: _ } => {
                  searched_pid == *pid && searched_syscall_number == *syscall_number  
                },
                _ => false
            }
        })
    }

    fn scroll_log_to_end(&mut self) -> iced::Task<Message> {
        scrollable::snap_to(
            scrollable::Id::new("log"),
            scrollable::RelativeOffset::END,
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

            let btn_paused = if self.is_paused {
                Some(button("continue").on_press(Message::BtnContinue))
            } else {
                None
            };

            Row::new()
                .align_y(iced::Center)
                .padding(5)
                .spacing(5)
                .push_maybe(execution_status)
                .push_maybe(btn_start)
                .push(horizontal_space())
                .push_maybe(btn_paused)
        };

        let tracer_log: Element<_> = {
            let t = self.log.iter().map(|log_item| {
                let font = Font { weight: iced::font::Weight::Bold, ..Font::MONOSPACE};
                let s = match log_item {
                    LogItem::Syscall { pid: _, syscall_number: _, args: _, ret_code: _, s } => s,
                    LogItem::Signal { pid: _, signal: _, s } => s,
                };
                let widget = text(s)
                    .color(color!(0x0000A0))
                    .font(font);
                Element::from(widget)
            });

            scrollable(column(t).spacing(2))
                .height(Fill)
                .width(Fill)
                .id(scrollable::Id::new("log"))
                .into()
        };

        column![
            top_row,
            horizontal_rule(5),
            tracer_log,
        ].into()
    }
}
