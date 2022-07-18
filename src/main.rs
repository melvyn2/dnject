use log::{debug, error, info, trace, warn};
use std::sync::Mutex;

use slint::{Model, ModelRc, SharedString, StandardListViewItem, VecModel, Weak};

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

fn file_prompt() -> SharedString {
    error!("stub file_prompt() called");
    SharedString::from(chrono::Local::now().format("%S").to_string())
}

fn add_library(list: ModelRc<StandardListViewItem>) -> ModelRc<StandardListViewItem> {
    let newlist = VecModel::from(list.iter().collect::<Vec<StandardListViewItem>>());
    newlist.insert(0, StandardListViewItem::from(file_prompt()));
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

    main.on_quit(slint::quit_event_loop);
    main.on_inject(inject);
    main.on_add_library(add_library);
    main.on_mod_library_list(mod_library_list);
    trace!("Callback bindings finished");

    info!("Starting event loop");
    main.run();
}
