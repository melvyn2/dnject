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

fn inject(target: StandardListViewItem, libs: ModelRc<StandardListViewItem>) {
    error!("stub inject() called");
}

fn file_prompt() -> SharedString {
    error!("stub file_prompt() called");
    SharedString::from(chrono::Local::now().format("%S").to_string())
}

fn modify_lib_list(handle: Weak<MainWindow>, op: SharedString, item: SharedString) {
    let handle = handle.unwrap();
    let mut idx = handle.get_lib_selected_index();
    let newlist: VecModel<StandardListViewItem> = VecModel::from(
        handle
            .get_lib_list()
            .iter()
            .collect::<Vec<StandardListViewItem>>(),
    );
    match op.as_str() {
        "add" => {
            newlist.insert(0, StandardListViewItem::from(item));
            handle.set_lib_selected_index(0);
        }
        "moveup" => {
            if idx <= 0 {
                return;
            }
            let item = newlist.row_data(idx as usize).unwrap();
            newlist.remove(idx as usize);
            idx -= 1;
            newlist.insert(idx as usize, item);
        }
        "remove" => {
            if idx < 0 {
                return;
            }
            newlist.remove(idx as usize);
            if idx > 0 {
                idx -= 1;
            }
        }
        other => {
            error!("Unknown operation '{}' passed to modify_lib_list()", other);
            return;
        }
    }
    handle.set_lib_list(ModelRc::new(newlist));
    handle.set_lib_selected_index(idx);
}

fn main() {
    trace!("Creating MainWindow");
    let main = MainWindow::new();

    let logger = SlintTextLogger(Mutex::new(main.as_weak()));
    log::set_boxed_logger(Box::new(logger))
        .map(|()| log::set_max_level(log::LevelFilter::Trace))
        .expect("Unable to init logger");
    trace!("Logger init done");

    let weak_handle = main.as_weak();
    main.on_quit(slint::quit_event_loop);
    main.on_inject(inject);
    main.on_modify_lib_list(move |op, item| modify_lib_list(weak_handle.clone(), op, item));
    main.on_file_prompt(file_prompt);
    trace!("Callback bindings finished");

    info!("Starting event loop");
    main.run();
}
