use std::io::{stdin, stdout, BufRead, Write};
use std::process::exit;

use libc::pid_t;

use mach2::kern_return::KERN_SUCCESS;
use mach2::traps::{mach_task_self, task_for_pid};

use mach_util::mach_portal::MachPortal;

use macos_portfetch_internal::STATUS_MESSAGES;

fn main() {
    let mut inp_iter = stdin().lock().lines();
    let pid_s = inp_iter.next().unwrap().unwrap();
    let bootstrap_name = inp_iter.next().unwrap().unwrap();
    drop(inp_iter);
    let pid = pid_s.parse::<pid_t>().unwrap();

    stdout().write_all(STATUS_MESSAGES[0]).unwrap();

    let p = MachPortal::connect(&bootstrap_name).unwrap();

    stdout().write_all(STATUS_MESSAGES[1]).unwrap();

    let mut port = 0;
    unsafe {
        match task_for_pid(mach_task_self(), pid, &mut port) {
            KERN_SUCCESS => stdout().write_all(STATUS_MESSAGES[2]).unwrap(),
            other => {
                print!("0x{:08x}", other);
                exit(1)
            }
        }
    };

    p.send_port(port).unwrap();

    stdout().write_all(STATUS_MESSAGES[3]).unwrap();
}
