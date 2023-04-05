use std::ffi::c_void;

use libc::{write, STDOUT_FILENO};

// Use libc write instead of rust stdout write because stdout struct may not exist
// See https://github.com/mmastrac/rust-ctor#warnings

#[ctor::ctor]
fn injected() {
    write_ascii_buf(testbin::INJECTED_MSG);
}

#[ctor::dtor]
fn ejected() {
    write_ascii_buf(testbin::EJECTED_MSG);
}

fn write_ascii_buf(buf: &[u8]) {
    unsafe { write(STDOUT_FILENO, buf.as_ptr() as *const c_void, buf.len()) };
}
