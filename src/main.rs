mod ui;
use ui::*;

fn main() {
    let main = MainWindow::new();
    main.on_quit(slint::quit_event_loop);
    main.run();
}
