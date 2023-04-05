use std::io::{stdout, Write};
use std::process::exit;
use std::thread::sleep;
use std::time::Duration;

mod common;

fn main() {
    stdout()
        .write_all(common::STARTUP_MSG)
        .unwrap_or_else(|_| exit(1));
    loop {
        sleep(Duration::from_secs(1))
    }
}
