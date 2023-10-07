use std::sync::atomic::{AtomicPtr, Ordering};

use log::{Level, LevelFilter, Log, Metadata, Record};

use qt_core::{qs, ConnectionType, GlobalColor, QPtr, SignalNoArgs, SignalOfQString};
use qt_gui::QColor;
use qt_widgets::{QTextEdit, SignalOfQColor};

#[derive(Debug)]
pub struct TextEditLogger {
    max_level: LevelFilter,
    append_signal_ptr: AtomicPtr<SignalOfQString>,
    text_color_signal_ptr: AtomicPtr<SignalOfQColor>,
}

impl TextEditLogger {
    pub unsafe fn new(text_edit: QPtr<QTextEdit>, max_level: LevelFilter) -> Self {
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
