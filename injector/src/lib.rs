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

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::ProcHandle;

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
