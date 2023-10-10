//! A cross-platform API to inject dynamic code objects into other processes.
//! All functionality resides in the [ProcHandle] struct

#![feature(core_intrinsics)]
#![feature(io_error_more)]
#![feature(optimize_attribute)]
#![feature(pointer_byte_offsets)]
#![feature(unchecked_math)]
#![feature(allocator_api)]
#![feature(ptr_as_uninit)]
#![feature(if_let_guard)]

use std::path::PathBuf;

use libc::c_void;

mod error;
pub use error::{InjectorError, InjectorErrorKind};

// On macOS and Linux, a module handle is an opaque pointer
// On windows, it is an HMODULE which is a pointer to the base address of the module in the target
pub type ModHandle = (PathBuf, *mut c_void);

// Ensure consistent API
trait InjectorTrait: Sized {
    fn new(cmd: Command) -> Result<Self, InjectorError>;

    fn inject(&mut self, libs: &[PathBuf]) -> Result<(), InjectorError>;

    fn eject(&mut self, handles: Option<&[ModHandle]>) -> Result<(), InjectorError>;

    unsafe fn eject_raw(&mut self, handles: &[*mut c_void]) -> Result<(), InjectorError>;

    fn current_modules(&self) -> &[ModHandle];

    fn kill(self) -> Result<(), InjectorError>;
}

// Import implementation for target

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::ProcHandle;
use std::process::Command;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::ProcHandle;

#[cfg(target_os = "windows")]
mod nt;
#[cfg(target_os = "windows")]
pub use nt::ProcHandle;
