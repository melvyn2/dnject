use qt_core::QBox;
use qt_core::QPtr;
use qt_core::SortOrder;

use qt_widgets::q_style::StandardPixmap;
use qt_widgets::*;

use qt_ui_tools::ui_form;

#[ui_form("../ui/main.ui")]
pub struct MainUI {
    // Top level widget
    pub widget: QBox<QWidget>,
    // Target/Inject screen switcher
    pub main_stack: QPtr<QStackedWidget>,
    // Target selector tabs
    pub target_tabs: QPtr<QTabWidget>,
    // Proc selector widgets
    pub proc_table: QPtr<QTreeWidget>,
    pub proc_owner_filter: QPtr<QCheckBox>,
    pub proc_refresh: QPtr<QPushButton>,
    // Launch control widgets
    pub exe_path_edit: QPtr<QComboBox>,
    pub exe_pick: QPtr<QToolButton>,
    pub cwd_path_edit: QPtr<QComboBox>,
    pub cwd_pick: QPtr<QToolButton>,
    // Wine mode widgets
    pub wine_mode_gbox: QPtr<QGroupBox>,
    pub wine_prefix: QPtr<QComboBox>,
    pub wine_loc: QPtr<QComboBox>,
    pub probe_button: QPtr<QPushButton>,
    // Target info & action widgets
    pub t_name: QPtr<QLabel>,
    pub t_status: QPtr<QLabel>,
    pub t_pid: QPtr<QLabel>,
    pub t_user: QPtr<QLabel>,
    pub t_exe: QPtr<QLabel>,
    pub t_type: QPtr<QLabel>,
    pub t_has_perms: QPtr<QLabel>,
    pub attach_button: QPtr<QPushButton>,
    pub kill_button: QPtr<QPushButton>,
    pub copy_or_launch_button: QPtr<QPushButton>,
    // Library inject widgets
    pub lib_list_layout: QPtr<QGridLayout>,
    pub lib_list: QPtr<QListWidget>,
    pub lib_add: QPtr<QToolButton>,
    pub lib_pick: QPtr<QToolButton>,
    pub lib_move: QPtr<QToolButton>,
    pub lib_del: QPtr<QToolButton>,
    pub inject_button: QPtr<QPushButton>,
    // Eject widgets
    pub module_list: QPtr<QTreeWidget>,
    pub eject_button: QPtr<QPushButton>,
    // Return to target selection
    pub return_button: QPtr<QPushButton>,
    // Log box widgets
    pub log_check: QPtr<QCheckBox>,
    pub log_box: QPtr<QTextEdit>,
}

impl MainUI {
    pub fn new() -> Self {
        let new = Self::load();
        unsafe {
            new.init();
        }
        new
    }
    unsafe fn init(&self) {
        // Set settings which can't be set in Qt Creator
        self.proc_table.sort_items(1, SortOrder::DescendingOrder);
        self.log_box.set_visible(false);

        self.proc_table.header().set_stretch_last_section(false);
        self.proc_table
            .header()
            .set_section_resize_mode_2a(0, q_header_view::ResizeMode::Stretch);
        self.proc_table.header().resize_section(1, 60);
        self.proc_table.header().resize_section(2, 60);

        macro_rules! set_standard_icon {
            ($button:ident, $icon:ident) => {
                self.$button.set_icon(
                    self.widget
                        .style()
                        .standard_icon_1a(StandardPixmap::$icon)
                        .as_ref(),
                );
            };
        }
        // Set icons for action buttons (those that interact with OS)
        set_standard_icon!(proc_refresh, SPBrowserReload);
        set_standard_icon!(exe_pick, SPDirIcon);
        set_standard_icon!(cwd_pick, SPDirIcon);
        set_standard_icon!(probe_button, SPFileDialogContentsView);
        set_standard_icon!(attach_button, SPMediaPlay);
        set_standard_icon!(kill_button, SPBrowserStop);
        set_standard_icon!(lib_pick, SPDirIcon);
        // This isn't an action button but I need an icon for it so w/e
        set_standard_icon!(lib_move, SPTitleBarShadeButton);
        set_standard_icon!(inject_button, SPMediaSeekForward);
        set_standard_icon!(eject_button, SPMediaSeekBackward);
    }
}
