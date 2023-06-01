#![feature(let_chains)]

use injector::ProcHandle;
use std::path::PathBuf;
use std::process::{exit, Child, Command, Stdio};

use libc::pid_t;

use sysinfo::{PidExt, ProcessExt, ProcessRefreshKind, RefreshKind, SystemExt};

fn show_usage(err: bool) -> ! {
    let exe_name = std::env::args()
        .next()
        .unwrap_or_else(|| env!("CARGO_BIN_NAME").to_string());
    println!("Usage:");
    println!(
        "\t{} --launch <executable> [arguments] -- <library> [more libraries ...]",
        exe_name
    );
    println!("\t{} --pid <PID> <library> [more libraries ...]", exe_name);
    println!(
        "\t{} --target <process name> <library> [more libraries ...]",
        exe_name
    );
    println!("Exit Codes:");
    println!("\t1: Invalid arguments");
    println!("\t2: Could not launch process");
    println!("\t3: Could not find target process");
    println!("\t4: Could not attach to process");
    println!("\t5: Could not inject to process");
    println!("\t6: Spawned process exited with error (when specific code is not available)");
    println!("\tExit code of child process is provided when available");
    exit(err as i32)
}

fn main() {
    let mut args = std::env::args_os();
    if args.len() < 4 {
        show_usage(false);
    }

    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Trace)
        .parse_default_env()
        .init();

    let op = args.nth(1).unwrap();
    match op.to_string_lossy().as_bytes() {
        b"--launch" => {
            #[derive(Eq, PartialEq)]
            enum TargetMode {
                // Normal,
                // PreInject,
                TaskForPid,
            }
            let next = args.next().unwrap_or_else(|| show_usage(true));
            let (mode, exe) = match next.to_string_lossy().to_string().as_str() {
                "--tfp" => (
                    TargetMode::TaskForPid,
                    args.next().unwrap_or_else(|| show_usage(true)),
                ),
                // Useless
                // "--pre" => (
                //     TargetMode::PreInject,
                //     args.next().unwrap_or_else(|| show_usage(true)),
                // ),
                _ => (TargetMode::TaskForPid, next),
            };

            // Read args until --
            let mut proc_args = vec![];
            while let Some(arg) = args.next() && arg != "--" {
                proc_args.push(arg);
            }

            // Collect remaining args as lib paths
            let libs: Vec<PathBuf> = args.map(|p| p.into()).collect();
            if libs.is_empty() {
                show_usage(true);
            }

            let mut cmd = Command::new(exe);
            cmd.args(proc_args);
            cmd.stdout(Stdio::inherit());
            cmd.stderr(Stdio::inherit());
            cmd.stdin(Stdio::inherit());
            let mut child: Option<Child> = None;
            let mut handle = match mode {
                // ProcHandle::new is broken
                // TargetMode::Normal => match ProcHandle::new(cmd) {
                //     Ok(p) => p,
                //     Err(e) => {
                //         eprintln!("{}", e);
                //         exit(2)
                //     }
                // },
                // TargetMode::PreInject => match ProcHandle::new_pre_inject(cmd, &libs) {
                //     Ok(p) => p,
                //     Err(e) => {
                //         eprintln!("{}", e);
                //         exit(2)
                //     }
                // },
                TargetMode::TaskForPid => {
                    let id = match cmd.spawn() {
                        Ok(c) => {
                            let id = c.id();
                            child = Some(c);
                            id
                        }
                        Err(e) => {
                            eprintln!("{}", e);
                            exit(2)
                        }
                    };
                    match ProcHandle::try_from(id as pid_t) {
                        Ok(h) => h,
                        Err(e) => {
                            eprintln!("{}", e);
                            exit(4)
                        }
                    }
                }
            };

            // if mode != TargetMode::PreInject {
            match handle.inject(&libs) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("{}", e);
                    exit(6)
                }
            }
            // };

            // if child.is_none() {
            //     child = handle.take_proc_child();
            // }
            child
                .unwrap()
                .wait()
                .map(|c| {
                    #[cfg(target_family = "unix")]
                    {
                        use std::os::unix::process::ExitStatusExt;
                        exit(c.into_raw());
                    }
                    #[cfg(not(target_family = "unix"))]
                    if c.success() {
                        exit(0);
                    } else {
                        exit(5);
                    }
                })
                .unwrap_or_else(|_| exit(0));
        }
        b"--pid" => {
            let pid = args
                .next()
                .unwrap_or_else(|| show_usage(true))
                .to_string_lossy()
                .parse::<u32>()
                .unwrap_or_else(|_| show_usage(true));

            let system = sysinfo::System::new_with_specifics(
                RefreshKind::new().with_processes(ProcessRefreshKind::new()),
            );

            if system.process(sysinfo::Pid::from(pid as usize)).is_none() {
                eprintln!("Could not find process with pid {}", pid);
                exit(3)
            }

            let mut handle = match injector::ProcHandle::try_from(pid as pid_t) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("{}", e);
                    exit(3)
                }
            };
            let libs: Vec<PathBuf> = args.map(|p| p.into()).collect();
            if libs.is_empty() {
                show_usage(true);
            }
            match handle.inject(&libs) {
                Ok(()) => exit(0),
                Err(e) => {
                    eprintln!("{}", e);
                    exit(4)
                }
            };
        }
        b"--target" => {
            let target = args
                .next()
                .unwrap_or_else(|| show_usage(true))
                .to_string_lossy()
                .to_string();
            let system = sysinfo::System::new_with_specifics(
                RefreshKind::new().with_processes(ProcessRefreshKind::new()),
            );
            let pid = system
                .processes_by_exact_name(&target)
                .next()
                .unwrap_or_else(|| {
                    eprintln!("No process found with name {}", target);
                    exit(3)
                })
                .pid()
                .as_u32();

            let mut handle = match injector::ProcHandle::try_from(pid as pid_t) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("{}", e);
                    exit(4)
                }
            };
            let libs: Vec<PathBuf> = args.map(|p| p.into()).collect();
            if libs.is_empty() {
                show_usage(true);
            }
            match handle.inject(&libs) {
                Ok(()) => exit(0),
                Err(e) => {
                    eprintln!("{}", e);
                    exit(5)
                }
            };
        }
        _ => show_usage(true),
    }
}
