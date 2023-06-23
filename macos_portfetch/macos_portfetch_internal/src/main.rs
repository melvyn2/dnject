use mach2::traps::{mach_task_self, task_for_pid};
use std::process::exit;

use mach_util::mach_portal::MachPortal;
use mach_util::mach_try;

use macos_portfetch_internal::{Input, StatusMessage};

fn main() {
    let mut stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let input: Input = match bincode::decode_from_std_read(&mut stdin, bincode::config::standard())
    {
        Ok(i) => {
            bincode::encode_into_std_write(
                StatusMessage::Parse(Ok(())),
                &mut stdout,
                bincode::config::standard(),
            )
            .unwrap();
            i
        }
        Err(e) => {
            bincode::encode_into_std_write(
                StatusMessage::Parse(Err(e.to_string())),
                &mut stdout,
                bincode::config::standard(),
            )
            .unwrap();
            exit(1);
        }
    };

    let portal = match MachPortal::connect(&input.bootstrap_name) {
        Ok(p) => {
            bincode::encode_into_std_write(
                StatusMessage::Connect(Ok(())),
                &mut stdout,
                bincode::config::standard(),
            )
            .unwrap();
            p
        }
        Err(e) => {
            bincode::encode_into_std_write(
                StatusMessage::Connect(Err(e)),
                &mut stdout,
                bincode::config::standard(),
            )
            .unwrap();
            exit(2);
        }
    };

    let mut port = 0;
    let r = unsafe { mach_try!(task_for_pid(mach_task_self(), input.target, &mut port)) };
    bincode::encode_into_std_write(
        StatusMessage::TFP(r.clone()),
        &mut stdout,
        bincode::config::standard(),
    )
    .unwrap();
    if r.is_err() {
        exit(3);
    }

    let r = portal.send_port(port);
    bincode::encode_into_std_write(
        StatusMessage::Send(r.clone()),
        &mut stdout,
        bincode::config::standard(),
    )
    .unwrap();
    if r.is_err() {
        exit(4);
    }
}
