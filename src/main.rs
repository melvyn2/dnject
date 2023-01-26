#![windows_subsystem = "windows"]

use std::cell::RefCell;
use std::ffi::CStr;
use std::mem::transmute;
use std::ops::Deref;
use std::rc::Rc;

use cpp_core::{CppBox, Ptr, StaticUpcast};

use qt_core::{
    q_event, qs, slot, CheckState, DropAction, QEvent, QObject, QString, QVariant, SlotNoArgs,
    SlotOfBool, SlotOfInt,
};
use qt_core_custom_events::custom_event_filter::CustomEventFilter;
use qt_gui::{QDragEnterEvent, QDropEvent};
use qt_widgets::*;

use sysinfo::{PidExt, ProcessExt, ProcessRefreshKind, RefreshKind, System, SystemExt, UserExt};

// mod old;
mod ui;
use ui::MainUI;

struct MainWindow {
    ui: MainUI,
    system_data: RefCell<System>,
    wine_prefix_saved: RefCell<String>,
    wine_loc_saved: RefCell<String>,
}

impl StaticUpcast<QObject> for MainWindow {
    unsafe fn static_upcast(ptr: Ptr<Self>) -> Ptr<QObject> {
        ptr.ui.widget.as_ptr().static_upcast()
    }
}

impl MainWindow {
    fn new() -> Rc<Self> {
        let new = Rc::new(Self {
            ui: MainUI::new(),
            system_data: RefCell::new(System::new_with_specifics(RefreshKind::new())),
            wine_prefix_saved: RefCell::new("".to_string()),
            wine_loc_saved: RefCell::new("".to_string()),
        });
        // Should be safe as this is guaranteed uninit object
        unsafe {
            new.init();
            new.on_refresh_clicked();
        }
        new
    }
    unsafe fn init(self: &Rc<Self>) {
        self.add_event_filters();

        self.bind_slots();

        self.ui.widget.show();
    }

    unsafe fn add_event_filters(self: &Rc<Self>) {
        let filter = CustomEventFilter::new(Self::lib_list_event_filter).into_raw_ptr();
        self.ui.lib_list.install_event_filter(filter);
    }

    #[allow(clippy::needless_return)]
    fn lib_list_event_filter(obj: &mut QObject, event: &mut QEvent) -> bool {
        // Function body has to be unsafe rather than function, because the closure requires an FnMut
        // Which only safe function pointers are
        unsafe {
            if event.type_() == q_event::Type::DragEnter {
                println!("Trace: received DragEnter event.");
                println!(
                    "Trace: Event parent object: {:?}",
                    CStr::from_ptr(obj.meta_object().class_name())
                );
                // Transmute is safe because we check the event type
                let drag_event: &mut QDragEnterEvent = transmute(event);
                let mime_data = drag_event.mime_data().text().to_std_string();
                let urls: Vec<&str> = mime_data.lines().collect();
                if drag_event.mime_data().has_urls()
                    && !urls.iter().all(|url| url.is_empty() || url.ends_with('/'))
                {
                    println!("Trace: event has valid data, accepting.");
                    drag_event.set_drop_action(DropAction::LinkAction);
                    drag_event.accept();
                    return true;
                }
            } else if event.type_() == q_event::Type::Drop {
                println!("Trace: received Drop event.");
                println!(
                    "Trace: parent object: {:?}",
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
            return false;
        }
    }

    unsafe fn bind_slots(self: &Rc<Self>) {
        self.ui
            .target_tabs
            .current_changed()
            .connect(&self.slot_on_tab_changed());
        self.ui
            .proc_owner_filter
            .toggled()
            .connect(&self.slot_on_refresh_clicked());

        self.ui
            .proc_refresh
            .clicked()
            .connect(&self.slot_on_refresh_clicked());
        self.ui
            .wine_check
            .toggled()
            .connect(&self.slot_on_wine_toggled());
        self.ui
            .lib_list
            .current_row_changed()
            .connect(&self.slot_on_lib_changed());
        self.ui.lib_add.clicked().connect(&self.slot_on_lib_add());
        self.ui.lib_pick.clicked().connect(&self.slot_on_lib_pick());
        self.ui.lib_move.clicked().connect(&self.slot_on_lib_move());
        self.ui.lib_del.clicked().connect(&self.slot_on_lib_del());
        self.ui
            .log_check
            .toggled()
            .connect(&self.slot_on_log_toggled());
    }

    #[slot(SlotOfInt)]
    unsafe fn on_tab_changed(self: &Rc<Self>, _: i32) {
        self.adjust_wine_inputs();
        println!("Error: no tab change handler impl!")
    }

    // TODO not working
    #[slot(SlotNoArgs)]
    unsafe fn on_refresh_clicked(self: &Rc<Self>) {
        self.ui.proc_table.clear();

        let ownership_filter = self.ui.proc_owner_filter.is_checked();
        let wine_mode = self.ui.wine_check.is_checked();

        let mut system = self.system_data.borrow_mut();
        system.refresh_specifics(
            RefreshKind::new()
                .with_processes(ProcessRefreshKind::new().with_user())
                .with_users_list(),
        );

        let cur_uid = system
            .processes()
            .iter()
            .find(|&(&pid, _)| pid == sysinfo::get_current_pid().unwrap())
            .unwrap()
            .1
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

    #[slot(SlotOfBool)]
    unsafe fn on_wine_toggled(self: &Rc<Self>, _: bool) {
        self.adjust_wine_inputs();
        println!("Error: wine mode unimpl!");
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
        println!("Error: adding libs unimpl!")
    }
    #[slot(SlotNoArgs)]
    unsafe fn on_lib_pick(self: &Rc<Self>) {
        println!("Error: lib picker unimpl!")
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

    unsafe fn adjust_wine_inputs(self: &Rc<Self>) {
        println!("Trace: adjust_wine_inputs called");

        let wine_box = self.ui.wine_check.check_state() == CheckState::Checked;
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
