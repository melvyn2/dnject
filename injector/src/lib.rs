//! A cross-platform API to inject dynamic code objects into other processes.
//! All functionality resides in the [ProcHandle] struct

#![feature(io_error_more)]
#![feature(optimize_attribute)]
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

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::ProcHandle;
use std::process::{Child, Command};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::ProcHandle;

#[cfg(target_os = "windows")]
mod nt;
#[cfg(target_os = "windows")]
pub use nt::ProcHandle;

// Ensure consistent API
// PIDs on all platforms are c_int or i32, so ensure they have the correct TryFrom trait from PIDs
trait InjectorTrait: Sized + TryFrom<i32> {
    fn new(cmd: Command) -> Result<Self, InjectorError>;

    fn inject(&mut self, libs: &[PathBuf]) -> Result<(), InjectorError>;

    fn eject(&mut self, handles: Option<&[ModHandle]>) -> Result<(), InjectorError>;

    unsafe fn eject_raw(&mut self, handles: &[*mut c_void]) -> Result<(), InjectorError>;

    fn current_modules(&self) -> &[ModHandle];

    fn child(&mut self) -> &mut Option<Child>;

    fn kill(self) -> Result<(), InjectorError>;
}

// Force API to be implemented (if unimplemented, the trait definition is called, and recurses)
#[deny(unconditional_recursion)]
impl InjectorTrait for ProcHandle {
    fn new(cmd: Command) -> Result<Self, InjectorError> {
        Self::new(cmd)
    }

    fn inject(&mut self, libs: &[PathBuf]) -> Result<(), InjectorError> {
        self.inject(libs)
    }

    fn eject(&mut self, handles: Option<&[ModHandle]>) -> Result<(), InjectorError> {
        self.eject(handles)
    }

    unsafe fn eject_raw(&mut self, handles: &[*mut c_void]) -> Result<(), InjectorError> {
        self.eject_raw(handles)
    }

    fn current_modules(&self) -> &[ModHandle] {
        self.current_modules()
    }

    fn child(&mut self) -> &mut Option<Child> {
        self.child()
    }

    fn kill(self) -> Result<(), InjectorError> {
        self.kill()
    }
}
