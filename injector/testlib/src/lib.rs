use std::ffi::c_void;

use libc::{write, STDOUT_FILENO};

// Use libc write instead of rust stdout write because stdout struct may not exist
// See https://github.com/mmastrac/rust-ctor#warnings

#[ctor::ctor]
fn injected() {
    write_ascii_buf(testbin::INJECTED_MSG);
}

// This only registers with atexit, not module unload
// #[ctor::dtor]
// fn ejected() {
//     write_ascii_buf(testbin::EJECTED_MSG);
// }

#[used]
#[cfg_attr(
    any(target_os = "linux", target_os = "android"),
    link_section = ".fini_array"
)]
#[cfg_attr(target_os = "freebsd", link_section = ".fini_array")]
#[cfg_attr(target_os = "netbsd", link_section = ".fini_array")]
#[cfg_attr(target_os = "openbsd", link_section = ".fini_array")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_term_func")]
// TODO find corresponding unload section
// #[cfg_attr(target_os = "windows", link_section = ".CRT$XCU")]
static FOO: extern "C" fn() = {
    extern "C" fn foo() {
        write_ascii_buf(testbin::EJECTED_MSG);
    }
    foo
};

fn write_ascii_buf(buf: &[u8]) {
    unsafe { write(STDOUT_FILENO, buf.as_ptr() as *const c_void, buf.len()) };
}
