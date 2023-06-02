#![feature(let_chains)]
#![feature(if_let_guard)]
#![windows_subsystem = "windows"]

use std::cell::RefCell;
use std::ffi::{c_int, c_void};
use std::io::ErrorKind;
use std::mem::transmute;
use std::ops::Deref;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::ptr::null_mut;
use std::rc::Rc;
use std::sync::atomic::{AtomicPtr, Ordering};

use log::{Level, LevelFilter, Log, Metadata, Record};

use cpp_core::{CppDeletable, Ptr, Ref, StaticUpcast};
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

use injector::{InjectorError, InjectorErrorKind, ModHandle, ProcHandle};

mod ui;
use crate::term_spawn::spawn_term;
use ui::MainUI;

mod term_spawn;

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
        if !self.enabled(record.metadata()) || record.metadata().target().contains("goblin") {
            return;
        }

        let log_line = format!("{} [{}] {}", record.level(), record.target(), record.args());
        // No dark mode detection, yay! White background is forced in .ui file
        let color = match record.level() {
            Level::Error => (GlobalColor::Red, 31),
            Level::Warn => (GlobalColor::DarkYellow, 33),
            Level::Info => (GlobalColor::Black, 39),
            Level::Debug => (GlobalColor::DarkGray, 90),
            Level::Trace => (GlobalColor::DarkBlue, 34),
        };

        // TODO windows?
        println!("\x1b[{}m{}\x1b[39;49m", color.1, log_line);

        let text_color_signal_ptr = self.text_color_signal_ptr.load(Ordering::Acquire);
        let append_signal_ptr = self.append_signal_ptr.load(Ordering::Acquire);
        unsafe {
            let text_color_signal = text_color_signal_ptr.as_ref().unwrap();
            text_color_signal.emit(&QColor::from_global_color(color.0));
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
    child_handle: RefCell<Option<Child>>,
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
            child_handle: RefCell::default(),
            target_process: RefCell::default(),
            target_handle: RefCell::default(),
            process_refresh_timer: RefCell::default(),
        });
        // Should be safe as this is guaranteed uninit object
        unsafe {
            new.qt_init();

            new.on_back_clicked();

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
        self.ui.exe_path_edit.line_edit().install_event_filter(
            CustomEventFilter::new(Self::path_box_event_filter).into_raw_ptr(),
        );
        self.ui.cwd_path_edit.line_edit().install_event_filter(
            CustomEventFilter::new(Self::path_box_event_filter).into_raw_ptr(),
        );
    }

    fn lib_list_event_filter(obj: &mut QObject, event: &mut QEvent) -> bool {
        // Function body has to be unsafe rather than function, because the closure requires an FnMut
        // Which only safe function pointers are
        unsafe {
            if event.type_() == q_event::Type::DragEnter {
                // SAFETY: Transmute is safe because we check the event type
                let drag_event: &mut QDragEnterEvent = transmute(event);
                if drag_event.mime_data().has_urls()
                    && !drag_event.mime_data().urls().iter().all(|url| {
                        url.is_empty() || url.to_string_0a().to_std_string().ends_with('/')
                    })
                {
                    // Accepting the DragEnter is necessary to receive the Drop event
                    drag_event.set_drop_action(DropAction::LinkAction);
                    drag_event.accept();
                    return true;
                }
            } else if event.type_() == q_event::Type::Drop {
                // SAFETY: Transmute is safe because we check the event type
                let drop_event: &mut QDropEvent = transmute(event);
                let paths = drop_event
                    .mime_data()
                    .urls()
                    .iter()
                    .map(|u| u.to_string_0a().to_std_string())
                    .filter(|f| !f.is_empty() && !f.ends_with('/'));
                // Safety: Transmute is safe because this event filter is only applied to a QListWidget
                let list_widget: &mut QListWidget = transmute(obj);
                for file in paths {
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

    fn path_box_event_filter(obj: &mut QObject, event: &mut QEvent) -> bool {
        unsafe {
            if event.type_() == q_event::Type::DragEnter {
                let drag_event: &mut QDragEnterEvent = transmute(event);
                if drag_event.mime_data().urls().count_0a() == 1 {
                    drag_event.set_drop_action(DropAction::LinkAction);
                    drag_event.accept();
                    return true;
                }
            } else if event.type_() == q_event::Type::Drop {
                let drop_event: &mut QDropEvent = transmute(event);
                // Safety: Transmute is safe because this event filter is only applied to a QLineEdit
                let list_widget: &mut QLineEdit = transmute(obj);
                list_widget.set_text(
                    drop_event
                        .mime_data()
                        .urls()
                        .first()
                        .to_string_0a()
                        .replace_2_q_string(&qs("file://"), &qs("")),
                );
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
        bind!(exe_pick, clicked, slot_on_exe_pick_clicked);
        bind!(cwd_pick, clicked, slot_on_cwd_pick_clicked);
        bind!(env_table, item_selection_changed, slot_on_env_selected);
        bind!(env_add_button, clicked, slot_on_env_add);
        bind!(env_del_button, clicked, slot_on_env_del);

        bind!(wine_mode_gbox, toggled, slot_on_wine_toggled);

        bind!(probe_button, clicked, slot_on_probe_clicked);

        bind!(
            copy_or_launch_button,
            clicked,
            slot_on_copy_or_launch_clicked
        );
        bind!(kill_button, clicked, slot_on_kill_clicked);
        bind!(attach_button, clicked, slot_on_attach_clicked);

        bind!(lib_list, current_row_changed, slot_on_lib_changed);
        bind!(lib_add, clicked, slot_on_lib_add);
        bind!(lib_pick, clicked, slot_on_lib_pick);
        bind!(lib_move, clicked, slot_on_lib_move);
        bind!(lib_del, clicked, slot_on_lib_del);
        bind!(inject_button, clicked, slot_on_inject_clicked);

        bind!(module_list, item_selection_changed, slot_on_module_selected);
        bind!(eject_button, clicked, slot_on_eject_clicked);

        bind!(return_button, clicked, slot_on_back_clicked);

        bind!(log_check, toggled, slot_on_log_toggled);
    }

    #[slot(SlotOfInt)]
    unsafe fn on_tab_changed(self: &Rc<Self>, idx: i32) {
        self.adjust_wine_inputs();
        match idx {
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
            .process(Pid::from(std::process::id() as usize))
            .unwrap()
            .user_id()
            .unwrap();

        for (&pid, proc) in system.processes() {
            if ownership_filter && proc.user_id().map(|uid| uid != cur_uid).unwrap_or(true) {
                continue;
            }
            // This doesn't leak because parent (QTreeWidget) drops the item
            let proc_item: Ptr<QTreeWidgetItem> =
                QTreeWidgetItem::from_q_tree_widget(&self.ui.proc_table).into_ptr();
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
        }
    }

    #[slot(SlotOfQString)]
    unsafe fn on_exe_text_updated(self: &Rc<Self>, text: Ref<QString>) {
        self.ui.probe_button.set_enabled(!text.is_empty())
    }

    #[slot(SlotNoArgs)]
    unsafe fn on_exe_pick_clicked(self: &Rc<Self>) {
        let mut filter = String::from("Windows Executable (*.exe);;Any file (*)");
        if cfg!(not(target_os = "windows")) {
            filter = format!("Unix Executable (*);;{}", filter);
        }

        let path = QFileDialog::get_open_file_name_6a(
            &self.ui.main,
            &qs("Select the target executable"),
            &qs(""),
            &qs(filter),
            &qs(""),
            q_file_dialog::Option::DontResolveSymlinks | q_file_dialog::Option::ReadOnly,
        );
        if !path.is_empty() {
            if cfg!(not(target_os = "windows")) {
                self.ui
                    .wine_mode_gbox
                    .set_checked(path.ends_with_q_string(&qs(".exe")));
            }
            self.ui
                .exe_path_edit
                .insert_item_int_q_string(0, &self.ui.exe_path_edit.current_text());
            self.ui.exe_path_edit.set_edit_text(&path);
        }
    }

    #[slot(SlotNoArgs)]
    unsafe fn on_cwd_pick_clicked(self: &Rc<Self>) {
        let path = QFileDialog::get_existing_directory_4a(
            &self.ui.main,
            &qs("Select a working directory in which to launch the target"),
            &qs(""),
            q_file_dialog::Option::ShowDirsOnly
                | q_file_dialog::Option::DontResolveSymlinks
                | q_file_dialog::Option::ReadOnly,
        );
        if !path.is_empty() {
            self.ui
                .cwd_path_edit
                .insert_item_int_q_string(0, &self.ui.cwd_path_edit.current_text());
            self.ui.cwd_path_edit.set_edit_text(&path);
        }
    }

    #[slot(SlotNoArgs)]
    unsafe fn on_env_selected(self: &Rc<Self>) {
        self.ui
            .env_del_button
            .set_enabled(!self.ui.env_table.selected_items().is_empty())
    }

    #[slot(SlotNoArgs)]
    unsafe fn on_env_add(self: &Rc<Self>) {
        let item: Ptr<QTreeWidgetItem> =
            QTreeWidgetItem::from_q_tree_widget(&self.ui.env_table).into_ptr();
        item.set_text(0, &qs(""));
        item.set_text(1, &qs(""));
        item.set_flags(item.flags() | ItemFlag::ItemIsEditable);
        // Unselect old items
        for old_item in self
            .ui
            .env_table
            .selected_items()
            .iter()
            .map(|p| Ptr::from_raw(*p))
        {
            self.ui.env_table.set_item_selected(old_item, false);
        }
        // Select new item
        self.ui.env_table.set_item_selected(item, true);
    }

    #[slot(SlotNoArgs)]
    unsafe fn on_env_del(self: &Rc<Self>) {
        for item in self
            .ui
            .env_table
            .selected_items()
            .iter()
            .map(|p| Ptr::from_raw(*p))
        {
            item.delete()
        }
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

    unsafe fn probe_pid(self: &Rc<Self>, target: Pid) -> Result<(), ()> {
        let mut system = self.system_data.borrow_mut();
        system.refresh_specifics(
            RefreshKind::new()
                .with_processes(ProcessRefreshKind::new().with_user())
                .with_users_list(),
        );

        let proc = match system.process(target) {
            Some(p) => p,
            None => {
                return Err(());
            }
        };

        self.target_process.replace(Some(target));

        self.ui.attach_button.set_enabled(true);

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
        log::warn!("Process type check not impl");
        Ok(())
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

                match self.probe_pid(Pid::from(pid as usize)) {
                    Ok(()) => {}
                    Err(_) => {
                        log::info!("Could not find process {}", pid);
                        QMessageBox::warning_q_widget2_q_string(
                            &self.ui.main,
                            &qs("Process not found"),
                            &qs("The process could not be located. It may have exited after the most recent refresh/probe."),
                        );
                        self.on_refresh_clicked();
                        return;
                    }
                };

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

                self.refresh_target_info();

                self.ui.main_stack.set_current_index(1);
            }
            1 => {
                self.ui
                    .exe_path_edit
                    .insert_item_int_q_string(0, &self.ui.exe_path_edit.current_text());
                self.ui
                    .cwd_path_edit
                    .insert_item_int_q_string(0, &self.ui.cwd_path_edit.current_text());

                self.ui.copy_or_launch_button.set_text(&qs("Launch"));
                self.ui.attach_button.set_text(&qs("Launch and Attach"));

                let exe_path = self.ui.exe_path_edit.current_text().to_std_string();

                self.ui
                    .t_exe
                    .set_text(&qs(format!("Executable: {}", exe_path)));
                // TODO probe
                // self.ui.t_has_perms.set_text(&qs());
                self.ui.t_status.set_text(&qs("Status: not launched"));
                // TODO probe
                // self.ui.t_type.set_text(&qs());

                log::warn!("Process type & perms check not impl");

                self.ui.main_stack.set_current_index(1);
            }
            other => log::error!("unexpected target tab index {}", other),
        }
    }

    unsafe fn create_target_cmd(self: &Rc<Self>) -> Result<Command, std::io::Error> {
        let exe_path = self.ui.exe_path_edit.current_text().to_std_string();
        let mut cmd = Command::new(exe_path);

        let cwd = self.ui.cwd_path_edit.current_text().to_std_string();
        if !cwd.is_empty() {
            cmd.current_dir(cwd);
        }

        if !self.ui.inherit_env_checkbox.is_checked() {
            cmd.env_clear();
        }
        for item in (0..self.ui.env_table.top_level_item_count())
            .map(|idx| self.ui.env_table.top_level_item(idx))
        {
            cmd.env(item.text(0).to_std_string(), item.text(1).to_std_string());
        }

        let tty_fd = spawn_term()?;
        cmd.stdout(tty_fd.try_clone()?);
        cmd.stderr(tty_fd.try_clone()?);
        cmd.stdin(tty_fd);

        Ok(cmd)
    }

    #[slot(SlotNoArgs)]
    unsafe fn on_copy_or_launch_clicked(self: &Rc<Self>) {
        match self.ui.target_tabs.current_index() {
            0 => {
                log::error!("copy to launch unimpl")
            }
            1 => {
                let child = match self.create_target_cmd().and_then(|mut c| c.spawn()) {
                    Ok(c) => c,
                    Err(e) => {
                        let err_str = format!("The target could not be launched: {}", e);
                        log::error!("{}", err_str);
                        QMessageBox::critical_q_widget2_q_string(
                            &self.ui.main,
                            &qs("Failed to launch target"),
                            &qs(err_str),
                        );
                        return;
                    }
                };

                match self.probe_pid(Pid::from(child.id() as usize)) {
                    Ok(()) => {}
                    Err(_) => {
                        log::info!("Could not locate launched process ({})", child.id());
                        QMessageBox::warning_q_widget2_q_string(
                        &self.ui.main,
                        &qs("Process not found"),
                        &qs("The launched process could not be located. It may have exited immediately."),
                        );
                        return;
                    }
                }

                self.child_handle.replace(Some(child));

                self.ui.copy_or_launch_button.set_enabled(false);
                self.ui.attach_button.set_text(&qs("Attach"));
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

        if !system.refresh_process(pid) {
            log::info!("PID {} no longer exists", pid);
            self.ui.t_status.set_text(&qs("Status: Exited"));
            // Don't keep refreshing because of PID reuse (fuck you apple)
            self.target_process.replace(None);
            self.ui.attach_button.set_enabled(false);
            drop(system);
            return;
        }
        let proc = system.process(pid).unwrap();

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
        let handle = self.target_handle.replace(None).unwrap();
        match handle.kill() {
            Ok(()) => {
                self.ui.kill_button.set_enabled(false);
                self.ui.lib_list_gbox.set_enabled(false);
                self.ui.module_list_gbox.set_enabled(false);
                self.refresh_target_info();
            }
            Err(e) => {
                let err_str = format!("The target process could not be killed to: {}", e);
                log::error!("{}", err_str);
                QMessageBox::critical_q_widget2_q_string(
                    &self.ui.main,
                    &qs("Failed to kill target"),
                    &qs(err_str),
                );
            }
        }
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
            return Err(Box::new(std::io::Error::new(
                ErrorKind::Unsupported,
                "attach not impl for platform",
            )));
        }
    }

    #[slot(SlotNoArgs)]
    unsafe fn on_attach_clicked(self: &Rc<Self>) {
        if self.target_process.borrow().is_some() {
            let mut handle = match self.attach() {
                Ok(p) => p,
                Err(e) => {
                    let err_str = format!("The target process could not be attached to: {}", e);
                    log::error!("{}", err_str);
                    QMessageBox::critical_q_widget2_q_string(
                        &self.ui.main,
                        &qs("Failed to attach to target"),
                        &qs(err_str),
                    );
                    return;
                }
            };
            log::info!("Attached to process {}", handle.get_pid());

            if let Some(child) = self.child_handle.replace(None) {
                handle.child().replace(child);
            }

            self.target_handle.replace(Some(handle));
            self.ui.attach_button.set_enabled(false);
            self.ui.kill_button.set_enabled(true);
            self.ui.lib_list_gbox.set_enabled(true);
            self.ui.module_list_gbox.set_enabled(true);
            self.ui.t_has_perms.set_text(&qs("Successfully attached"));
        } else {
            // ProcHandle::new just launches and calls task_for_pid anyways, so use dnject attach logic
            if cfg!(target_os = "macos") {
                self.on_copy_or_launch_clicked();
                if self.target_process.borrow().is_some() {
                    self.on_attach_clicked();
                }
                return;
            }
            let mut handle = match self
                .create_target_cmd()
                .map_err(InjectorError::from)
                .and_then(ProcHandle::new)
            {
                Ok(c) => c,
                Err(e) => {
                    let err_str = format!("The target could not be launched or attached to: {}", e);
                    log::error!("{}", err_str);
                    QMessageBox::critical_q_widget2_q_string(
                        &self.ui.main,
                        &qs("Failed to launch or attach to target"),
                        &qs(err_str),
                    );
                    return;
                }
            };

            let pid = handle.child().as_ref().unwrap().id();
            match self.probe_pid(Pid::from(pid as usize)) {
                Ok(()) => {}
                Err(_) => {
                    log::info!("Could not locate launched process ({})", pid);
                    QMessageBox::warning_q_widget2_q_string(
                        &self.ui.main,
                        &qs("Process not found"),
                        &qs("The launched process could not be located. It may have exited immediately."),
                    );
                }
            }
        }
    }

    #[slot(SlotOfInt)]
    unsafe fn on_lib_changed(self: &Rc<Self>, idx: i32) {
        if self.ui.lib_list.count() > 0 {
            self.ui.lib_list.set_style_sheet(&qs(""));
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
        let filter = if cfg!(target_os = "windows") || self.ui.wine_mode_gbox.is_checked() {
            "Dynamic Link Library (*.dll);;Any file (*)"
        } else if cfg!(target_os = "macos") {
            "Dynamic Library (*.dylib);;Any file (*)"
        } else {
            "Shared Object (*.so);;Any file(*)"
        };

        let paths = QFileDialog::get_open_file_names_6a(
            &self.ui.main,
            &qs("Select libraries to inject"),
            &qs(""),
            &qs(filter),
            &qs(""),
            q_file_dialog::Option::DontResolveSymlinks | q_file_dialog::Option::ReadOnly,
        );

        let list_widget = &self.ui.lib_list;

        while !paths.is_empty() {
            let file = paths.take_first();
            if !file.is_empty() {
                list_widget.add_item_q_string(file.replace_2_q_string(&qs("file://"), &qs("")));
                let new_item = list_widget.item(list_widget.count() - 1);
                new_item.set_flags(new_item.flags() | ItemFlag::ItemIsEditable);
                self.ui.lib_list.set_style_sheet(&qs(""));
                self.ui.inject_button.set_enabled(true);
            }
        }
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
            Ok(()) => {
                self.ui.lib_list.clear();
                self.on_lib_changed(-1);
            }
            Err(e) => {
                if let InjectorErrorKind::PartialSuccess(idx) = e.kind() {
                    for i in 0..*idx {
                        self.ui.lib_list.take_item(i as c_int).delete();
                    }
                };
                QMessageBox::critical_q_widget2_q_string(
                    &self.ui.main,
                    &qs("Failed to inject"),
                    &qs(e.to_string()),
                );
            }
        };
        drop(handle_ref);
        self.update_modules()
    }

    #[slot(SlotNoArgs)]
    unsafe fn on_module_selected(self: &Rc<Self>) {
        if self.ui.module_list.selected_items().count_0a() > 0 {
            self.ui.eject_button.set_text(&qs("Eject Selected"));
        } else {
            self.ui.eject_button.set_text(&qs("Eject All"));
        }
    }

    unsafe fn update_modules(self: &Rc<Self>) {
        let mut handle_ref = self.target_handle.borrow_mut();
        let handle = handle_ref.as_mut().unwrap();
        self.ui
            .eject_button
            .set_enabled(!handle.current_modules().is_empty());
        self.ui.module_list.clear();
        for (path, handle) in handle.current_modules() {
            let mod_item: Ptr<QTreeWidgetItem> =
                QTreeWidgetItem::from_q_tree_widget(&self.ui.module_list).into_ptr();
            mod_item.set_text(0, &qs(path.file_name().unwrap().to_string_lossy()));
            mod_item.set_text(1, &QString::number_u64_int(*handle as u64, 16));
        }
    }

    #[slot(SlotNoArgs)]
    unsafe fn on_eject_clicked(self: &Rc<Self>) {
        let module_items: Box<dyn Iterator<Item = Ptr<QTreeWidgetItem>>> =
            if self.ui.module_list.selected_items().count_0a() > 0 {
                Box::new(
                    self.ui
                        .module_list
                        .selected_items()
                        .iter()
                        .map(|p| Ptr::from_raw(*p)),
                )
            } else {
                Box::new(
                    (0..self.ui.module_list.top_level_item_count())
                        .map(|idx| self.ui.module_list.top_level_item(idx)),
                )
            };

        let handles = module_items
            .map(|item| {
                (
                    PathBuf::from(item.text(0).to_std_string()),
                    item.text(1).to_u_long_long_2a(null_mut(), 16) as *mut c_void,
                )
            })
            .collect::<Vec<ModHandle>>();

        let mut prochandle_ref = self.target_handle.borrow_mut();
        let prochandle = prochandle_ref.as_mut().unwrap();
        match prochandle.eject(Some(&handles)) {
            Ok(()) => {}
            Err(e) => {
                let err_str = format!("Module(s) could not be ejected: {}", e);
                log::error!("{}", err_str);
                QMessageBox::critical_q_widget2_q_string(
                    &self.ui.main,
                    &qs("Failed to eject modules"),
                    &qs(err_str),
                );
                return;
            }
        }
        drop(prochandle_ref);
        self.update_modules();
    }

    #[slot(SlotNoArgs)]
    unsafe fn on_back_clicked(self: &Rc<Self>) {
        self.child_handle.replace(None);
        self.target_handle.replace(None);
        self.target_process.replace(None);

        self.ui.t_name.set_text(&qs("Name:"));
        self.ui.t_pid.set_text(&qs("PID:"));
        self.ui.t_exe.set_text(&qs("Executable:"));
        self.ui.t_has_perms.set_text(&qs("Can Attach:"));
        self.ui.t_status.set_text(&qs("Status:"));
        self.ui.t_user.set_text(&qs("Owner:"));
        self.ui.t_type.set_text(&qs("Type:"));

        self.ui
            .copy_or_launch_button
            .set_text(&qs("Copy to Launch"));
        self.ui.kill_button.set_enabled(false);
        self.ui.attach_button.set_text(&qs("Attach"));
        self.ui.attach_button.set_enabled(true);

        self.ui.lib_list_gbox.set_enabled(false);
        self.ui.lib_list.clear();
        self.ui
            .lib_list
            .set_style_sheet(&qs("background-color: rgba(0,0,0,0)"));
        self.ui.inject_button.set_enabled(false);

        self.ui.module_list_gbox.set_enabled(false);
        self.ui.module_list.clear();
        self.ui.eject_button.set_enabled(false);

        self.ui.main_stack.set_current_index(0);
        self.on_refresh_clicked();
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
