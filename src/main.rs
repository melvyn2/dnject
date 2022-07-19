use std::sync::Mutex;

use log::{error, info, trace, warn};

use slint::{Model, ModelRc, SharedString, StandardListViewItem, VecModel, Weak};
use sysinfo::{Pid, PidExt, Process, ProcessExt, ProcessRefreshKind, System, SystemExt, UserExt};

mod ui;
use ui::*;

struct SlintTextLogger(Mutex<Weak<MainWindow>>);

impl log::Log for SlintTextLogger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let timestamp = chrono::Local::now().format("%T%.6f");
        let rec_string = format!("[{}] {} - {}\n", timestamp, record.level(), record.args());
        print!("{}", rec_string);
        let handle_lock = self.0.lock();
        match handle_lock {
            Ok(handle) => handle.unwrap().invoke_log(SharedString::from(rec_string)),
            Err(err) => println!(
                "[{}] ERROR - Failed to unlock MainWindow handle mutex in logger: {}",
                timestamp, err
            ),
        };
    }

    fn flush(&self) {}
}

fn fetch_proc_list(mode: SharedString) -> ModelRc<StandardListViewItem> {
    let mut system = System::new();
    system.refresh_processes_specifics(ProcessRefreshKind::with_user(ProcessRefreshKind::new()));
    system.refresh_users_list();

    let mut procs: Vec<(&Pid, &Process)> = system
        .processes()
        .iter()
        .filter(|(_, proc)| !proc.exe().as_os_str().is_empty()) // Filters out kernel threads
        .collect::<Vec<_>>();
    procs.sort_by_key(|(pid, _)| (-1i32 as u32) - pid.as_u32());

    let mut user_filter = false;

    // Filter processes based on combobox setting
    match mode.as_str() {
        "Owned Processes" => {
            let cur_pid = &sysinfo::get_current_pid().unwrap();
            let cur_proc = &system.processes()[cur_pid];
            let cur_user = cur_proc.user_id().unwrap();
            procs.retain(|(_, proc)| proc.user_id().map_or(false, |uid| uid == cur_user));
            user_filter = true;
        }
        "Wine Processes" => {
            procs.retain(|(_, proc)| proc.exe().ends_with("wine-preloader"));
        }
        "All Processes" => {}
        other => warn!("Unexpected filter setting {:?}", other),
    }

    info!("Filtered {} to {} processes", mode.as_str(), procs.len());

    let list = VecModel::default();
    for (pid, proc) in procs {
        // TODO this could be better done by a view with columns (which slint doesn't have)
        let entry = if user_filter {
            format!("{} [{}]", proc.name(), pid)
        } else {
            format!(
                "{} [{}] ({})",
                proc.name(),
                pid,
                proc.user_id().map_or("?".to_string(), |uid| system
                    .get_user_by_id(uid)
                    .map_or(uid.to_string(), |user| user.name().to_string()))
            )
        };
        list.push(StandardListViewItem::from(SharedString::from(entry)));
    }

    ModelRc::new(list)
}

fn file_prompt() -> SharedString {
    error!("stub file_prompt() called");
    SharedString::from(chrono::Local::now().format("%S").to_string())
}

fn add_library(list: ModelRc<StandardListViewItem>) -> ModelRc<StandardListViewItem> {
    let path = file_prompt();
    trace!("Adding library path {:?}", path);
    let newlist = VecModel::from(list.iter().collect::<Vec<StandardListViewItem>>());
    newlist.insert(0, StandardListViewItem::from(path));
    ModelRc::new(newlist)
}

fn mod_library_list(
    list: ModelRc<StandardListViewItem>,
    idx: i32,
    moveup: bool,
) -> ModelRc<StandardListViewItem> {
    let newlist = VecModel::from(list.iter().collect::<Vec<StandardListViewItem>>());
    let item = newlist.row_data(idx as usize).unwrap();
    // Our ui callback does bounds checking already
    newlist.remove(idx as usize);
    if moveup {
        newlist.insert((idx - 1) as usize, item);
    }
    ModelRc::new(newlist)
}

fn inject(target: StandardListViewItem, libs: ModelRc<StandardListViewItem>) {
    trace!(
        "inject({:?}, {:?})",
        target.text,
        libs.iter().map(|x| x.text).collect::<Vec<SharedString>>()
    );
    error!("stub inject() called");
}

fn main() {
    trace!("Creating MainWindow");
    let main = MainWindow::new();

    let logger = SlintTextLogger(Mutex::new(main.as_weak()));
    log::set_boxed_logger(Box::new(logger))
        .map(|()| log::set_max_level(log::LevelFilter::Trace))
        .expect("Unable to init logger");
    trace!("Logger init done");

    main.on_fetch_proc_list(fetch_proc_list);
    main.on_add_library(add_library);
    main.on_mod_library_list(mod_library_list);
    main.on_inject(inject);
    main.on_quit(slint::quit_event_loop);
    trace!("Callback bindings finished");

    let modes = VecModel::from(vec![SharedString::from("Owned Processes")]);
    #[cfg(target_os = "linux")]
    modes.push(SharedString::from("Wine Processes"));
    modes.push(SharedString::from("All Processes"));
    // TODO when elevation is added, make All Processes default when euid == 0
    main.set_proc_sel(modes.row_data(0).unwrap());
    main.set_proc_modes(ModelRc::new(modes));

    main.invoke_refresh_proc_list();
    trace!("Populated UI elements");

    info!("Starting event loop");
    main.run();
}
