#![windows_subsystem = "windows"]

use std::cell::RefCell;
use std::ffi::{c_int, CStr};
use std::io::ErrorKind;
use std::mem::transmute;
use std::ops::Deref;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicPtr, Ordering};

use log::{Level, LevelFilter, Log, Metadata, Record};

use cpp_core::{CppBox, Ptr, Ref, StaticUpcast};
use libc::pid_t;

use qt_core::{
    q_event, qs, slot, ConnectionType, DropAction, GlobalColor, ItemFlag, QBox, QEvent, QObject,
    QOperatingSystemVersion, QPtr, QString, QTimer, QVariant, SignalNoArgs, SignalOfQString,
    SlotNoArgs, SlotOfBool, SlotOfInt, SlotOfQString,
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
        ptr.ui.main.as_ptr().static_upcast()
    }
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

        self.ui.main.show();
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
                log::trace!("received DragEnter event");
                log::trace!(
                    "event parent object: {:?}",
                    CStr::from_ptr(obj.meta_object().class_name())
                );
                // Transmute is safe because we check the event type
                let drag_event: &mut QDragEnterEvent = transmute(event);
                let mime_data = drag_event.mime_data().text().to_std_string();
                let urls: Vec<&str> = mime_data.lines().collect();
                if drag_event.mime_data().has_urls()
                    && !urls
                        .into_iter()
                        .all(|url| url.is_empty() || url.ends_with('/'))
                {
                    log::trace!("event has valid urls, accepting");
                    drag_event.set_drop_action(DropAction::LinkAction);
                    drag_event.accept();
                    return true;
                }
            } else if event.type_() == q_event::Type::Drop {
                log::trace!("received Drop event");
                log::trace!(
                    "parent object: {:?}",
                    CStr::from_ptr(obj.meta_object().class_name())
                );
                // Transmute is safe because we check the event type
                let drop_event: &mut QDropEvent = transmute(event);
                let mime_data = drop_event.mime_data().text().to_std_string();
                let urls: Vec<&str> = mime_data.lines().collect();
                let list_widget: &mut QListWidget = transmute(obj);
                for file in urls.into_iter().filter(|f| !f.ends_with('/')) {
                    list_widget.add_item_q_string(&qs(file.replacen("file://", "", 1)));
                    let new_item = list_widget.item(list_widget.count() - 1);
                    new_item.set_flags(new_item.flags() | ItemFlag::ItemIsEditable);
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
        macro_rules! bind {
            ($widget:ident, $signal:ident, $slot:ident) => {
                // TODO remove slot_ prefix
                self.ui.$widget.$signal().connect(&self.$slot());
            };
        }

        bind!(target_tabs, current_changed, slot_on_tab_changed);

        bind!(
            proc_table,
            item_selection_changed,
            slot_on_proc_table_selection
        );
        bind!(
            proc_table,
            item_selection_changed,
            slot_on_proc_table_selection
        );
        bind!(
            proc_table,
            item_double_clicked,
            slot_on_proc_table_item_double_clicked
        );
        bind!(proc_owner_filter, toggled, slot_on_refresh_clicked);
        bind!(proc_refresh, clicked, slot_on_refresh_clicked);

        bind!(
            exe_path_edit,
            current_text_changed,
            slot_on_exe_text_updated
        );

        bind!(wine_mode_gbox, toggled, slot_on_wine_toggled);

        bind!(probe_button, clicked, slot_on_probe_clicked);

        bind!(kill_button, clicked, slot_on_kill_clicked);
        bind!(attach_button, clicked, slot_on_attach_clicked);

        bind!(lib_list, current_row_changed, slot_on_lib_changed);
        bind!(lib_add, clicked, slot_on_lib_add);
        bind!(lib_pick, clicked, slot_on_lib_pick);
        bind!(lib_move, clicked, slot_on_lib_move);
        bind!(lib_del, clicked, slot_on_lib_del);
        bind!(inject_button, clicked, slot_on_inject_clicked);

        bind!(return_button, clicked, slot_on_back_clicked);

        bind!(log_check, toggled, slot_on_log_toggled);
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
        // let wine_mode = self.ui.wine_mode_gbox.is_checked();

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
                &match proc.effective_user_id() {
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

    #[cfg(target_os = "macos")]
    fn expl_available() -> bool {
        let feat = cfg!(feature = "macos-ent-bypass");
        let ver = unsafe { QOperatingSystemVersion::current() };
        let ver_match = unsafe {
            (ver.major_version() == 12) && (ver.minor_version() < 7)
                || ((ver.minor_version() == 7) && ver.micro_version() < 2)
        };
        feat && ver_match
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
                let proc = system.process(Pid::from_u32(pid));

                if proc.is_none() {
                    log::info!("Could not find process {}", pid);
                    QMessageBox::warning_q_widget2_q_string(
                        &self.ui.main,
                        &qs("Process not found"),
                        &qs("The process could not be located. It may have exited after the most recent refresh."),
                    );
                    drop(system);
                    self.on_refresh_clicked();
                    return;
                }

                let proc = proc.unwrap();

                self.target_process.replace(Some(Pid::from_u32(pid)));
                self.ui.attach_button.set_enabled(true);

                self.ui.main_stack.set_current_index(1);
                self.ui.t_pid.set_text(&qs(format!("PID: {}", proc.pid())));
                self.ui
                    .t_exe
                    .set_text(&qs(format!("Executable: {}", proc.exe().to_string_lossy())));
                self.ui
                    .t_exe
                    .set_tool_tip(&qs(proc.exe().to_string_lossy()));

                let user = match proc.effective_user_id() {
                    Some(uid) => match system.get_user_by_id(uid) {
                        Some(user) => format!("{} ({})", user.name(), uid.to_string()),
                        None => uid.to_string(),
                    },
                    None => "(unknown)".to_string(),
                };

                self.ui.t_user.set_text(&qs(format!("Owner: {}", user)));
                // TODO check target arch & wine
                // self.ui.t_type.set_text(&qs());
                // TODO check target euid & ents (on macos)
                #[cfg(target_os = "macos")]
                let status = {
                    match macos_portfetch::ProbeInfo::new(pid as pid_t) {
                        Err(e) => format!("Unknown ({})", e),
                        Ok(sec) => match (sec.same_euid, sec.hardened, sec.get_task_allow) {
                            (_, true, false) => {
                                if Self::expl_available() {
                                    "Admin Required (Hardened + exploit)"
                                } else {
                                    "No Access (Hardened)"
                                }
                            }
                            (false, _, _) => "Admin Required (Different user)",
                            (true, true, true) => "OK (Hardened + allow)",
                            (true, false, true) => "OK (Explicit allow)",
                            (true, false, false) => "OK (Not protected)",
                        }
                        .to_string(),
                    }
                };
                #[cfg(not(target_os = "macos"))]
                let status = "unknown";
                self.ui
                    .t_has_perms
                    .set_text(&qs(format!("Can Attach: {}", status)));

                self.ui
                    .copy_or_launch_button
                    .set_text(&qs("Copy to Launch"));

                drop(system);

                self.refresh_target_info();
                log::warn!("Process type check not impl")
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

                self.ui.copy_or_launch_button.set_text(&qs("Launch"));
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
                .with_processes(ProcessRefreshKind::new())
                .with_users_list(),
        );

        let proc = match system.process(pid) {
            Some(p) => p,
            None => {
                log::info!("PID {} no longer exists", pid);
                self.ui.t_status.set_text(&qs("Status: Exited"));
                // Don't keep refreshing because of PID reuse (fuck you apple)
                self.target_process.replace(None);
                self.ui.attach_button.set_enabled(false);
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
    }

    #[slot(SlotNoArgs)]
    unsafe fn on_kill_clicked(self: &Rc<Self>) {
        let handle = self.target_handle.replace(None);
        handle.unwrap().kill();
    }

    // Wrap function to have single error handling branch
    fn attach(self: &Rc<Self>) -> Result<ProcHandle, Box<dyn std::error::Error>> {
        #[cfg(target_os = "macos")]
        {
            let status: String = unsafe { self.ui.t_has_perms.text() }.to_std_string();
            let pid = self.target_process.borrow().unwrap().as_u32() as pid_t;
            let port = if status.contains("No Access") {
                return Err(Box::new(std::io::Error::new(
                    ErrorKind::PermissionDenied,
                    "process is hardened",
                )));
            } else if status.contains("Admin Required") {
                if Self::expl_available() {
                    #[allow(unreachable_code)]
                    #[cfg(not(feature = "macos-ent-bypass"))]
                    return unreachable!();
                    #[cfg(feature = "macos-ent-bypass")]
                    macos_portfetch::get_port_admin_exploit(pid)?
                } else {
                    macos_portfetch::get_port_signed_admin(pid)?
                }
            } else {
                macos_portfetch::get_port_signed(pid)?
            };
            Ok(ProcHandle::try_from(port)?)
        }
        #[cfg(not(target_os = "macos"))]
        {
            log::error!("attach not impl for platform");
            return;
        }
    }

    #[slot(SlotNoArgs)]
    unsafe fn on_attach_clicked(self: &Rc<Self>) {
        let handle = match self.attach() {
            Ok(p) => p,
            Err(e) => {
                QMessageBox::critical_q_widget2_q_string(
                    &self.ui.main,
                    &qs("Failed to attach to target"),
                    &qs(format!(
                        "The target process process could not be attached to: {}",
                        e
                    )),
                );
                return;
            }
        };
        log::info!("Attached to process {}", handle.get_pid());
        self.target_handle.replace(Some(handle));
        self.ui.attach_button.set_enabled(false);
        self.ui.kill_button.set_enabled(true);
        self.ui.lib_list_gbox.set_enabled(true);
        self.ui.t_has_perms.set_text(&qs("Successfully attached"));
    }

    #[slot(SlotOfInt)]
    unsafe fn on_lib_changed(self: &Rc<Self>, idx: i32) {
        if self.ui.lib_list.count() > 0 {
            self.ui
                .lib_list
                .set_style_sheet(qt_core::QString::new().as_ref());
            self.ui.inject_button.set_enabled(true);
            self.ui.lib_move.set_enabled(idx > 0);
            self.ui.lib_del.set_enabled(idx >= 0);
        } else {
            self.ui
                .lib_list
                .set_style_sheet(&qs("background-color: rgba(0,0,0,0)"));
            self.ui.inject_button.set_enabled(false);
            self.ui.lib_move.set_enabled(false);
            self.ui.lib_del.set_enabled(false);
        }
    }
    #[slot(SlotNoArgs)]
    unsafe fn on_lib_add(self: &Rc<Self>) {
        self.ui.lib_list.add_item_q_string(qs("").as_ref());
        let new_item = self.ui.lib_list.item(self.ui.lib_list.count() - 1);
        new_item.set_flags(new_item.flags() | ItemFlag::ItemIsEditable);
        self.ui
            .lib_list
            .set_current_row_1a(self.ui.lib_list.count() - 1);
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
        let mut handle_ref = self.target_handle.borrow_mut();
        let handle = handle_ref.as_mut().unwrap();
        let paths: Vec<PathBuf> = (0..self.ui.lib_list.count())
            .map(|idx| PathBuf::from(self.ui.lib_list.item(idx).text().to_std_string()))
            .collect();
        match handle.inject(&paths) {
            Ok(()) => self.ui.lib_list.clear(),
            Err(e) => {
                QMessageBox::critical_q_widget2_q_string(
                    &self.ui.main,
                    &qs("Failed to inject"),
                    &qs(e.to_string()),
                );
            }
        };
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
        self.ui.main.adjust_size();
        if !state {
            self.ui
                .main
                .resize_2a(self.ui.main.width(), self.ui.main.height() - 100)
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
