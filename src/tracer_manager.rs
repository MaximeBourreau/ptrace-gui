use clap::Parser;
use nix::unistd::{ForkResult, Pid, fork};
use ptrace_gui::{
    Tracer,
    args::{Args, Command},
    message::Message,
    run_tracee,
};
use std::io;

pub fn run() -> (
    std::sync::mpsc::Sender<()>,
    std::sync::mpsc::Sender<Pid>,
    tokio::sync::mpsc::Receiver<Message>,
) {
    let (sender_to_gui, receiver_to_gui) = tokio::sync::mpsc::channel::<Message>(1000);

    let (sender_do_start, receiver_do_start) = std::sync::mpsc::channel::<()>();
    let (sender_do_step, receiver_do_step) = std::sync::mpsc::channel::<Pid>();

    let args = Args::parse();

    let command = {
        let Command::External(c) = &args.command;
        c.clone()
    };

    std::thread::spawn(move || {
        let output = io::stdout();

        let mut tracer = {
            let sender_to_gui = sender_to_gui.clone();

            Tracer::new(args, output, sender_to_gui, receiver_do_step).unwrap()
        };

        // the tracer (and the traced program) can be executed multiple times with this loop

        loop {
            // waiting for the user action to start (or restart) the tracer
            if receiver_do_start.recv().is_err() {
                break;
            }

            // run the traced program

            let pid = match unsafe { fork() } {
                Ok(ForkResult::Child) => {
                    let _ = run_tracee(&command, &[], &None);
                    break;
                }
                Ok(ForkResult::Parent { child }) => child,
                Err(err) => {
                    std::process::exit(-1);
                }
            };

            // tell the user the tracee pid

            sender_to_gui
                .blocking_send(Message::TraceeProcessCreated(pid))
                .unwrap();

            // run the tracer

            let _ = tracer.run_tracer(pid);

            // tell the user the tracer (and the traced program) has terminated

            // TODO: pass the return value of run_tracer in the TracerDone message
            sender_to_gui.blocking_send(Message::TracerDone).unwrap();
        }
    });

    (sender_do_start, sender_do_step, receiver_to_gui)
}
