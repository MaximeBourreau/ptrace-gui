use console::Style;
use lurk_cli::{
    args::Args,
    style::StyleConfig,
    syscall_info::{
        RetCode,
        SyscallArg,
        SyscallArgs,
    },
    tracer_event::TracerEvent,
    Tracer,
};
use nix::{
    unistd::{
        fork,
        ForkResult,
        Pid,
    },
    sys::signal::Signal,
};
use std::{
    cell::RefCell,
    collections::HashSet,
    io,
    rc::Rc,
};
use syscalls::Sysno;
use iced::{
    color, widget::{
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

// As a teaching tool, it can be smart not to show every system calls
// TODO maybe a whitelist instead ?
const HIDDEN_SYSCALLS_LIST: [Sysno; 1] = [
    // Sysno::arch_prctl,
    // Sysno::set_tid_address,
    Sysno::set_robust_list,
    // Sysno::rseq,
    // Sysno::prlimit64,
    // Sysno::mprotect,
    // Sysno::getrandom,
];

#[derive(Debug, Clone)]
enum Message {

    BtnStart,
    ReceivedSyscallEnter(Pid, Sysno, SyscallArgs, bool),
    ReceivedSyscallExit(Pid, Sysno, RetCode), // TODO : add Duration
    ReceivedTermination(Pid, Signal),
    BtnContinue,
    TracerDone,
}

fn main() {

    let (sender_to_gui, receiver_to_gui) = mpsc::channel::<Message>(1000);

    let (sender_do_start, mut receiver_do_start) = mpsc::channel::<()>(1);
    let (sender_do_step, mut receiver_do_step) = mpsc::channel::<()>(1);

    std::thread::spawn(move || {

        let is_step_by_step = Rc::new(RefCell::new(false));

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

        let hidden_syscalls = HashSet::from(HIDDEN_SYSCALLS_LIST);

        let mut tracer = {
            let sender_to_gui = sender_to_gui.clone();
            let is_step_by_step = is_step_by_step.clone();

            Tracer::new(
                args,
                output,
                style,
                Box::new(move |tracer_event| {

                    match tracer_event {
                        TracerEvent::SyscallEnter(pid, syscall_number, syscall_args) => {
                            if !hidden_syscalls.contains(&syscall_number) {

                                let should_pause: bool = {
                                    let mut is_step_by_step = is_step_by_step.borrow_mut();
                                    if *is_step_by_step == false && syscall_number == Sysno::write {
                                        *is_step_by_step = true;
                                    }
                                    *is_step_by_step
                                };

                                sender_to_gui.blocking_send(Message::ReceivedSyscallEnter(pid, syscall_number, syscall_args, should_pause)).unwrap();

                                if should_pause {
                                    // waits for the user to complete this step
                                    receiver_do_step.blocking_recv();
                                }
                            }
                        }
                        TracerEvent::SyscallExit(pid, syscall_number, ret_code) => {
                            if !hidden_syscalls.contains(&syscall_number) {
                                sender_to_gui.blocking_send(Message::ReceivedSyscallExit(pid, syscall_number, ret_code)).unwrap();
                            }
                        }
                        TracerEvent::Termination(pid, signal) => {
                            sender_to_gui.blocking_send(Message::ReceivedTermination(pid, signal)).unwrap();
                        }
                    }

                })
            ).unwrap()
        };

        let command = std::env::args().nth(1).unwrap();

        // the tracer (and the traced program) can be executed multiple times with this loop

        loop {

            // initialization : run the tracer whithout pause at the beginning
            {
                let mut is_step_by_step = is_step_by_step.borrow_mut();
                *is_step_by_step = false;
            }

            // waiting for the user action to start (or restart) the tracer
            if receiver_do_start.blocking_recv().is_none() {
                break;
            }

            // run the traced program
            
            let pid = match unsafe { fork() } {
                Ok(ForkResult::Child) => {
                    let _ = lurk_cli::run_tracee(&[command], &[], &None);
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

            // allows to check that the fork is done at the right time
            // TODO : remove for release
            eprintln!("[LOG] tracee pid={}", pid);

            // run the tracer

            let _ = tracer.run_tracer(pid);

            // tell the user the tracer (and the traced program) has terminated

            sender_to_gui.blocking_send(Message::TracerDone).unwrap();

        }
    });

    let _ = iced::application("lurk-gui", AppGui::update, AppGui::view)
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

struct AppGui {
    tracer_log: Vec<(Option<i32>, String)>,
    state: RunningState,
    /*
    is_first_start: bool,
    is_running: bool,
    is_first_exec_done: bool,
    */
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
                tracer_log: Vec::new(),
                /*
                is_first_start: true,
                is_running: false,
                is_first_exec_done: false,
                */
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
                self.tracer_log.clear();
                let _ = self.sender_do_start.try_send(());
                Task::none()
            }

            Message::ReceivedSyscallEnter(pid, syscall_number, syscall_args, should_pause) => {

                self.is_paused = should_pause;

                let args: String = {
                    // let syscall_args = syscall_enter_info.clone().args.0;
                    let v: Vec<String> = syscall_args.0
                        .iter()
                        .map(|arg| {
                            match arg {
                                SyscallArg::Int(v) => format!("{}", *v), // TODO hex and bit representation
                                SyscallArg::Str(v) => format!("{:?}", v),
                                SyscallArg::Addr(v) => {
                                    if *v == 0 {
                                        String::from("NULL")
                                    } else {
                                        String::from("addr")
                                    }
                                },
                            }
                        })
                        .collect();
                    v.join(",")
                };

                self.append_log(Some(pid.as_raw()), format!("{} {}({}) ...", pid.as_raw(), syscall_number, args))
            }

            Message::ReceivedSyscallExit(pid, syscall_number, ret_code) => {

                // check if this syscall is exec
                if self.state == RunningState::RunningWithoutFirstExec && syscall_number == Sysno::execve {
                    self.state = RunningState::Running;
                    // TODO : remove for release
                    eprintln!("[LOG] first exec done");
                }

                let msg = format!(
                    "{}  ...{} → {}",
                    pid.as_raw(),
                    syscall_number,
                    ret_code,
                );

                // TODO show syscall_info.duration

                self.append_log(Some(pid.as_raw()), msg)
            }

            Message::ReceivedTermination(pid, signal) => {
                self.append_log(None, format!("{} received signal {}", pid.as_raw(), signal))
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

    fn append_log(&mut self, pid: Option<i32>, msg: String) -> iced::Task<Message> {
        self.tracer_log.push((pid, msg));
        scrollable::snap_to(
            scrollable::Id::new("tracer_log"),
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
            let t = self.tracer_log.iter().map(|s| {
                let font = Font { weight: iced::font::Weight::Bold, ..Font::MONOSPACE};
                let widget = text(s.1.clone())
                    .color(color!(0x0000A0))
                    .font(font);
                Element::from(widget)
            });

            scrollable(column(t).spacing(2))
                .height(Fill)
                .width(Fill)
                .id(scrollable::Id::new("tracer_log"))
                .into()
        };

        column![
            top_row,
            horizontal_rule(5),
            tracer_log,
        ].into()
    }
}
