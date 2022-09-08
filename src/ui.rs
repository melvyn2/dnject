use qt_core::QBox;
use qt_core::QPtr;
use qt_core::SortOrder;

use qt_widgets::q_style::StandardPixmap;
use qt_widgets::*;

use qt_ui_tools::ui_form;

#[ui_form("../ui/main.ui")]
pub struct MainUI {
    pub widget: QBox<QWidget>,
    pub target_tabs: QPtr<QTabWidget>,
    pub target_pick: QPtr<QPushButton>,
    pub proc_table: QPtr<QTreeWidget>,
    pub proc_refresh: QPtr<QPushButton>,
    pub wine_check: QPtr<QCheckBox>,
    pub wine_prefix: QPtr<QComboBox>,
    pub wine_loc: QPtr<QComboBox>,
    pub lib_list: QPtr<QListWidget>,
    pub lib_add: QPtr<QToolButton>,
    pub lib_pick: QPtr<QToolButton>,
    pub lib_move: QPtr<QToolButton>,
    pub lib_del: QPtr<QToolButton>,
    pub log_check: QPtr<QCheckBox>,
    pub inject: QPtr<QPushButton>,
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
        set_standard_icon!(proc_refresh, SPBrowserReload);
        set_standard_icon!(target_pick, SPDirIcon);
        set_standard_icon!(lib_pick, SPDirIcon);
        set_standard_icon!(lib_move, SPTitleBarShadeButton);
        set_standard_icon!(lib_del, SPTrashIcon);
        set_standard_icon!(inject, SPMediaSeekForward);
    }
}
