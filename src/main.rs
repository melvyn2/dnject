#![windows_subsystem = "windows"]

use std::cell::RefCell;
use std::ffi::{c_int, CStr};
use std::mem::transmute;
use std::ops::Deref;
use std::rc::Rc;
use std::sync::atomic::{AtomicPtr, Ordering};

use log::{Level, LevelFilter, Log, Metadata, Record};

use cpp_core::{CppBox, Ptr, Ref, StaticUpcast};

use qt_core::{
    q_event, qs, slot, ConnectionType, DropAction, GlobalColor, QBox, QEvent, QObject, QPtr,
    QString, QTimer, QVariant, SignalNoArgs, SignalOfQString, SlotNoArgs, SlotOfBool, SlotOfInt,
    SlotOfQString,
};
use qt_core_custom_events::custom_event_filter::CustomEventFilter;
use qt_gui::{QColor, QDragEnterEvent, QDropEvent};
use qt_widgets::*;

use sysinfo::{
    Pid, PidExt, ProcessExt, ProcessRefreshKind, RefreshKind, System, SystemExt, UserExt,
};

use injector::ProcHandle;

mod ui;
use ui::MainUI;

struct MainWindow {
    ui: MainUI,
    system_data: RefCell<System>,
    wine_prefix_saved: RefCell<String>,
    wine_loc_saved: RefCell<String>,
    target_process: RefCell<Option<Pid>>,
    target_handle: RefCell<Option<ProcHandle>>,
    process_refresh_timer: RefCell<Option<QBox<QTimer>>>,
}

impl StaticUpcast<QObject> for MainWindow {
    unsafe fn static_upcast(ptr: Ptr<Self>) -> Ptr<QObject> {
        ptr.ui.widget.as_ptr().static_upcast()
    }
}

#[derive(Debug)]
struct TextEditLogger {
    max_level: LevelFilter,
    append_signal_ptr: AtomicPtr<SignalOfQString>,
    text_color_signal_ptr: AtomicPtr<SignalOfQColor>,
}

impl TextEditLogger {
    unsafe fn new(text_edit: QPtr<QTextEdit>, max_level: LevelFilter) -> Self {
        log::set_max_level(max_level);

        let clear_signal = SignalNoArgs::new();
        clear_signal.connect_with_type(ConnectionType::QueuedConnection, text_edit.slot_clear());
        clear_signal.emit();

        let append_signal = SignalOfQString::new();
        append_signal.connect_with_type(ConnectionType::QueuedConnection, text_edit.slot_append());
        let text_color_signal = SignalOfQColor::new();
        text_color_signal.connect_with_type(
            ConnectionType::QueuedConnection,
            text_edit.slot_set_text_color(),
        );
        Self {
            // into_raw_ptr "leaks" the box so the underlying object won't get deleted
            // Therefore this ptr is never null and its pointed data never uninitialized
            append_signal_ptr: AtomicPtr::new(append_signal.into_raw_ptr()),
            text_color_signal_ptr: AtomicPtr::new(text_color_signal.into_raw_ptr()),
            max_level,
        }
    }
}

impl Log for TextEditLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.max_level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let log_line = format!("{} [{}] {}", record.level(), record.target(), record.args());
        // No dark mode detection, yay! White background is forced in .ui file
        let color = match record.level() {
            Level::Error => GlobalColor::Red,
            Level::Warn => GlobalColor::DarkYellow,
            Level::Info => GlobalColor::Black,
            Level::Debug => GlobalColor::DarkGray,
            Level::Trace => GlobalColor::DarkBlue,
        };

        let text_color_signal_ptr = self.text_color_signal_ptr.load(Ordering::Acquire);
        let append_signal_ptr = self.append_signal_ptr.load(Ordering::Acquire);
        unsafe {
            let text_color_signal = text_color_signal_ptr.as_ref().unwrap();
            text_color_signal.emit(&QColor::from_global_color(color));
            let append_signal = append_signal_ptr.as_ref().unwrap();
            append_signal.emit(&qs(log_line));
        };
    }

    fn flush(&self) {}
}

impl MainWindow {
    fn new() -> Rc<Self> {
        let new = Rc::new(Self {
            ui: MainUI::new(),
            system_data: RefCell::new(System::new_with_specifics(RefreshKind::new())),
            wine_prefix_saved: RefCell::new("".to_string()),
            wine_loc_saved: RefCell::new("".to_string()),
            target_process: RefCell::default(),
            target_handle: RefCell::default(),
            process_refresh_timer: RefCell::default(),
        });
        // Should be safe as this is guaranteed uninit object
        unsafe {
            new.qt_init();
            new.on_refresh_clicked();
            let logger = Box::new(TextEditLogger::new(
                new.ui.log_box.clone(),
                LevelFilter::Trace,
            ));
            log::set_boxed_logger(logger).unwrap();
            log::trace!("Text logger initialized")
        }
        new
    }

    unsafe fn qt_init(self: &Rc<Self>) {
        self.add_event_filters();

        self.bind_slots();

        let timer = QTimer::new_0a();
        timer.timeout().connect(&self.slot_refresh_target_info());
        timer.start_1a(1000);
        self.process_refresh_timer.replace(Some(timer));

        self.ui.widget.show();
    }

    unsafe fn add_event_filters(self: &Rc<Self>) {
        self.ui.lib_list.install_event_filter(
            CustomEventFilter::new(Self::lib_list_event_filter).into_raw_ptr(),
        );
    }

    fn lib_list_event_filter(obj: &mut QObject, event: &mut QEvent) -> bool {
        // Function body has to be unsafe rather than function, because the closure requires an FnMut
        // Which only safe function pointers are
        unsafe {
            if event.type_() == q_event::Type::DragEnter {
                log::trace!("received DragEnter event.");
                log::trace!(
                    "Event parent object: {:?}",
                    CStr::from_ptr(obj.meta_object().class_name())
                );
                // Transmute is safe because we check the event type
                let drag_event: &mut QDragEnterEvent = transmute(event);
                let mime_data = drag_event.mime_data().text().to_std_string();
                let urls: Vec<&str> = mime_data.lines().collect();
                if drag_event.mime_data().has_urls()
                    && !urls.iter().all(|url| url.is_empty() || url.ends_with('/'))
                {
                    log::trace!("event has valid data, accepting.");
                    drag_event.set_drop_action(DropAction::LinkAction);
                    drag_event.accept();
                    return true;
                }
            } else if event.type_() == q_event::Type::Drop {
                log::trace!("received Drop event.");
                log::trace!(
                    "parent object: {:?}",
                    CStr::from_ptr(obj.meta_object().class_name())
                );
                // Transmute is safe because we check the event type
                let drop_event: &mut QDropEvent = transmute(event);
                let mime_data = drop_event.mime_data().text().to_std_string();
                let urls: Vec<&str> = mime_data.lines().collect();
                let list_widget: &mut QListWidget = transmute(obj);
                for file in urls.iter().filter(|f| !f.ends_with('/')) {
                    list_widget.add_item_q_string(qs(file.replacen("file://", "", 1)).as_ref());
                }
                list_widget.set_current_row_1a(list_widget.count() - 1);
                drop_event.set_drop_action(DropAction::LinkAction);
                drop_event.accept();
                return true;
            }
        }
        false
    }

    unsafe fn bind_slots(self: &Rc<Self>) {
        self.ui
            .target_tabs
            .current_changed()
            .connect(&self.slot_on_tab_changed());

        self.ui
            .proc_table
            .item_selection_changed()
            .connect(&self.slot_on_proc_table_selection());
        self.ui
            .proc_table
            .item_double_clicked()
            .connect(&self.slot_on_proc_table_item_double_clicked());
        self.ui
            .proc_owner_filter
            .toggled()
            .connect(&self.slot_on_refresh_clicked());
        self.ui
            .proc_refresh
            .clicked()
            .connect(&self.slot_on_refresh_clicked());

        self.ui
            .exe_path_edit
            .current_text_changed()
            .connect(&self.slot_on_exe_text_updated());

        self.ui
            .wine_mode_gbox
            .toggled()
            .connect(&self.slot_on_wine_toggled());

        self.ui
            .probe_button
            .clicked()
            .connect(&self.slot_on_probe_clicked());

        self.ui
            .lib_list
            .current_row_changed()
            .connect(&self.slot_on_lib_changed());
        self.ui.lib_add.clicked().connect(&self.slot_on_lib_add());
        self.ui.lib_pick.clicked().connect(&self.slot_on_lib_pick());
        self.ui.lib_move.clicked().connect(&self.slot_on_lib_move());
        self.ui.lib_del.clicked().connect(&self.slot_on_lib_del());
        self.ui
            .inject_button
            .clicked()
            .connect(&self.slot_on_inject_clicked());

        self.ui
            .return_button
            .clicked()
            .connect(&self.slot_on_back_clicked());

        self.ui
            .log_check
            .toggled()
            .connect(&self.slot_on_log_toggled());
    }

    #[slot(SlotOfInt)]
    unsafe fn on_tab_changed(self: &Rc<Self>, _idx: i32) {
        self.adjust_wine_inputs();
        match _idx {
            0 => self.on_proc_table_selection(),
            1 => self
                .ui
                .probe_button
                .set_enabled(!self.ui.exe_path_edit.current_text().is_empty()),
            other => log::error!("unexpected target tab index {}", other),
        }
    }

    #[slot(SlotNoArgs)]
    unsafe fn on_proc_table_selection(self: &Rc<Self>) {
        self.ui
            .probe_button
            .set_enabled(!self.ui.proc_table.selected_items().is_empty());
    }

    #[slot(SlotOfQTreeWidgetItemInt)]
    unsafe fn on_proc_table_item_double_clicked(
        self: &Rc<Self>,
        _item: Ptr<QTreeWidgetItem>,
        _idx: c_int,
    ) {
        // Hopefully there's no way to select a different item than the one double clicked
        self.on_probe_clicked()
    }

    // TODO not working
    #[slot(SlotNoArgs)]
    unsafe fn on_refresh_clicked(self: &Rc<Self>) {
        self.ui.proc_table.clear();

        let ownership_filter = self.ui.proc_owner_filter.is_checked();
        let wine_mode = self.ui.wine_mode_gbox.is_checked();

        let mut system = self.system_data.borrow_mut();
        system.refresh_specifics(
            RefreshKind::new()
                .with_processes(ProcessRefreshKind::new().with_user())
                .with_users_list(),
        );

        let cur_uid = system
            .process(Pid::from_u32(std::process::id()))
            .unwrap()
            .user_id()
            .unwrap();

        for (&pid, proc) in system.processes() {
            if ownership_filter && proc.user_id().map(|uid| uid != cur_uid).unwrap_or(true) {
                continue;
            }
            let proc_item: CppBox<QTreeWidgetItem> = QTreeWidgetItem::new();
            proc_item.set_text(0, &qs(proc.name()));
            // Use data rather than text to allow sorting
            proc_item.set_data(1, 0, &QVariant::from_uint(pid.as_u32()));
            proc_item.set_text(
                2,
                &match proc.user_id() {
                    Some(uid) => match system.get_user_by_id(uid) {
                        Some(user) => qs(user.name()),
                        None => QString::number_uint(*uid.deref()),
                    },
                    None => qs(""),
                },
            );
            self.ui
                .proc_table
                .insert_top_level_item(0, proc_item.into_ptr());
        }
    }

    #[slot(SlotOfQString)]
    unsafe fn on_exe_text_updated(self: &Rc<Self>, text: Ref<QString>) {
        self.ui.probe_button.set_enabled(!text.is_empty())
    }

    #[slot(SlotOfBool)]
    unsafe fn on_wine_toggled(self: &Rc<Self>, _: bool) {
        self.adjust_wine_inputs();
        log::error!("wine mode unimpl");
    }

    unsafe fn adjust_wine_inputs(self: &Rc<Self>) {
        log::trace!("adjust_wine_inputs called");

        let wine_box = self.ui.wine_mode_gbox.is_checked();
        let tab = self.ui.target_tabs.current_index();
        let wine_editable = wine_box && tab == 1;

        // Only save when leaving editable mode
        if (self.ui.wine_loc.is_editable() || self.ui.wine_prefix.is_editable()) && !wine_editable {
            self.save_wine_params();
        }
        self.ui.wine_prefix.set_enabled(wine_editable);
        self.ui.wine_loc.set_enabled(wine_editable);
        if wine_editable {
            self.restore_wine_params();
        } else {
            self.ui.wine_prefix.set_edit_text(&qs(""));
            self.ui.wine_loc.set_edit_text(&qs(""));
        }
    }

    unsafe fn save_wine_params(self: &Rc<Self>) {
        let pfx_cur = self.ui.wine_prefix.current_text().to_std_string();
        let loc_cur = self.ui.wine_loc.current_text().to_std_string();
        if !pfx_cur.trim().is_empty() {
            self.wine_prefix_saved.replace(pfx_cur);
        }
        if !loc_cur.trim().is_empty() {
            self.wine_loc_saved.replace(loc_cur);
        }
    }

    unsafe fn restore_wine_params(self: &Rc<Self>) {
        self.ui
            .wine_prefix
            .set_current_text(qs::<&str>(self.wine_prefix_saved.borrow().as_ref()).as_ref());
        self.ui
            .wine_loc
            .set_current_text(qs::<&str>(self.wine_loc_saved.borrow().as_ref()).as_ref());
    }

    #[slot(SlotNoArgs)]
    unsafe fn on_probe_clicked(self: &Rc<Self>) {
        match self.ui.target_tabs.current_index() {
            0 => {
                let proc_line = self.ui.proc_table.selected_items().take_first();
                let pid = proc_line.data(1, 0).to_u_int_0a();
                let mut system = self.system_data.borrow_mut();
                system.refresh_specifics(
                    RefreshKind::new()
                        .with_processes(ProcessRefreshKind::new().with_user())
                        .with_users_list(),
                );
                let proc_exists = system.process(Pid::from_u32(pid)).is_some();
                drop(system);

                if !proc_exists {
                    log::info!("Could not find process {}", pid);
                    QMessageBox::warning_q_widget2_q_string(
                        &self.ui.widget,
                        &qs("Process not found"),
                        &qs("The process could not be located. It may have exited after the most recent refresh."),
                    );
                    self.on_refresh_clicked();
                    return;
                }

                self.target_process.replace(Some(Pid::from_u32(pid)));

                self.ui.main_stack.set_current_index(1);
                self.refresh_target_info();
                log::warn!("Process type and perms checking not impl")
            }
            1 => {
                dbg!(self.ui.exe_path_edit.current_text().to_std_string());
                dbg!(self.ui.exe_path_edit.line_edit().text().to_std_string());
                self.ui
                    .exe_path_edit
                    .insert_item_int_q_string(0, &self.ui.exe_path_edit.current_text());
                self.ui
                    .cwd_path_edit
                    .insert_item_int_q_string(0, &self.ui.cwd_path_edit.current_text());
                log::error!("launch probe handler unimpl")
            }
            other => log::error!("unexpected target tab index {}", other),
        }
    }

    #[slot(SlotNoArgs)]
    unsafe fn refresh_target_info(self: &Rc<Self>) {
        // Don't refresh if not in view
        if self.ui.main_stack.current_index() != 1 {
            return;
        }

        let pid = match *self.target_process.borrow() {
            None => return,
            Some(pid) => pid,
        };
        let mut system = self.system_data.borrow_mut();

        system.refresh_specifics(
            RefreshKind::new()
                .with_processes(ProcessRefreshKind::new().with_user())
                .with_users_list(),
        );

        let proc = match system.process(pid) {
            Some(p) => p,
            None => {
                log::info!("PID {} no longer exists", pid);
                self.ui.t_status.set_text(&qs("Status: Exited"));
                // Don't keep refreshing because of PID reuse (fuck you apple)
                self.target_process.replace(None);
                drop(system);
                return;
            }
        };

        self.ui
            .t_name
            .set_text(&qs(format!("Name: {}", proc.name())));
        self.ui.t_status.set_text(&qs(format!(
            "Status: {}",
            proc.status().to_string().replace("Runnable", "Running")
        )));
        self.ui.t_pid.set_text(&qs(format!("PID: {}", proc.pid())));
        self.ui
            .t_exe
            .set_text(&qs(format!("Executable: {}", proc.exe().to_string_lossy())));
        self.ui
            .t_exe
            .set_tool_tip(&qs(proc.exe().to_string_lossy()));

        let user = match proc.user_id() {
            Some(uid) => match system.get_user_by_id(uid) {
                Some(user) => format!("{} ({})", user.name(), uid.to_string()),
                None => uid.to_string(),
            },
            None => "(unknown)".to_string(),
        };

        self.ui.t_user.set_text(&qs(format!("Owner: {}", user)));
        // TODO check target arch & wine
        // self.ui.t_type.set_text(&qs());
        // TODO check target uid & ents (on macos)
        // self.ui.t_has_perms.set_text(&qs());

        self.ui
            .copy_or_launch_button
            .set_text(&qs(match self.ui.target_tabs.current_index() {
                0 => "Copy to Launch",
                1 => "Launch",
                other => {
                    log::error!("unexpected target tab index {}", other);
                    return;
                }
            }));
    }

    #[slot(SlotOfInt)]
    unsafe fn on_lib_changed(self: &Rc<Self>, _: i32) {
        if self.ui.lib_list.count() > 0 {
            self.ui
                .lib_list
                .set_style_sheet(qt_core::QString::new().as_ref());
        }
    }
    #[slot(SlotNoArgs)]
    unsafe fn on_lib_add(self: &Rc<Self>) {
        self.ui.lib_list.add_item_q_string(qs("").as_ref());
        self.ui
            .lib_list
            .set_current_row_1a(self.ui.lib_list.count() - 1);
        log::error!("adding libs unimpl")
    }
    #[slot(SlotNoArgs)]
    unsafe fn on_lib_pick(self: &Rc<Self>) {
        log::error!("lib picker unimpl")
    }
    #[slot(SlotNoArgs)]
    unsafe fn on_lib_move(self: &Rc<Self>) {
        let row = self.ui.lib_list.current_row();
        if row > 0 {
            self.ui
                .lib_list
                .insert_item_int_q_list_widget_item(row - 1, self.ui.lib_list.take_item(row));
            self.ui.lib_list.set_current_row_1a(row - 1);
        }
    }
    #[slot(SlotNoArgs)]
    unsafe fn on_lib_del(self: &Rc<Self>) {
        self.ui.lib_list.take_item(self.ui.lib_list.current_row());
    }

    #[slot(SlotNoArgs)]
    unsafe fn on_inject_clicked(self: &Rc<Self>) {
        dbg!("inject clicked");
    }

    #[slot(SlotNoArgs)]
    unsafe fn on_back_clicked(self: &Rc<Self>) {
        self.target_handle.replace(None);
        self.target_process.replace(None);
        self.on_refresh_clicked();
        self.ui.main_stack.set_current_index(0);
    }

    #[slot(SlotOfBool)]
    unsafe fn on_log_toggled(self: &Rc<Self>, state: bool) {
        self.ui.log_box.set_visible(state);
        self.ui.widget.adjust_size();
        if !state {
            self.ui
                .widget
                .resize_2a(self.ui.widget.width(), self.ui.widget.height() - 100)
        }
    }
}

fn main() {
    // "Qt WebEngine seems to be initialized from a plugin. Please set Qt::AA_ShareOpenGLContexts
    // using QCoreApplication::setAttribute before constructing QGuiApplication."
    unsafe {
        qt_core::QCoreApplication::set_attribute_1a(
            qt_core::ApplicationAttribute::AAShareOpenGLContexts,
        )
    };
    QApplication::init(|_q_app| unsafe {
        let _main_ui = MainWindow::new();
        QApplication::exec()
    })
}
