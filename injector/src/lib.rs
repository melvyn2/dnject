//! A cross-platform API to inject dynamic code objects into other processes.
//! All functionality resides in the [ProcHandle] struct

#![feature(const_cstr_methods)]
#![feature(core_intrinsics)]
#![feature(io_error_more)]
#![feature(optimize_attribute)]
#![feature(pointer_byte_offsets)]
#![feature(unchecked_math)]
#![feature(allocator_api)]
#![feature(ptr_as_uninit)]
#![feature(extern_types)]
#![feature(if_let_guard)]

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{ModHandle, ProcHandle};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::ProcHandle;

// #[cfg(all(feature = "wine", target_family = "unix"))]
// pub mod wine;

#[cfg(target_os = "windows")]
mod nt;
#[cfg(target_os = "windows")]
pub use nt::ProcHandle;

#[derive(Debug, Clone)]
pub enum InjectorErrorKind {
    InvalidArchitecture,
    AttachFailure,
    AttachPermission,
    InvalidProcessHandle,
    // Index of invalid handles
    ModuleHandlesNotOwned(Vec<usize>),
    TooManyModules,
    RemoteFailure,
    PartialSuccess(usize),
    IoError(std::io::ErrorKind),
    Unknown,
}

pub struct InjectorError {
    kind: InjectorErrorKind,
    msg: String,
}

impl std::fmt::Debug for InjectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.msg)
    }
}

impl std::fmt::Display for InjectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl std::error::Error for InjectorError {}

impl From<std::io::Error> for InjectorError {
    fn from(value: std::io::Error) -> Self {
        Self {
            kind: InjectorErrorKind::IoError(value.kind()),
            msg: value.to_string(),
        }
    }
}

impl InjectorError {
    fn new<S: ToString>(kind: InjectorErrorKind, msg: S) -> Self {
        Self {
            kind,
            msg: msg.to_string(),
        }
    }

    pub fn kind(&self) -> &InjectorErrorKind {
        &self.kind
    }
}
