use std::ops::Deref;

use mach2::mach_port::{mach_port_deallocate, mach_port_mod_refs};
use mach2::port::{mach_port_t, MACH_PORT_RIGHT_SEND};
use mach2::traps::mach_task_self;

use mach_util::mach_try;

/// A wrapper struct for [mach_port_t], which ties Rust `clone` and `drop` to mach port refcounts
pub struct TaskPort {
    inner: mach_port_t,
}

impl Clone for TaskPort {
    fn clone(&self) -> Self {
        unsafe { mach_port_mod_refs(mach_task_self(), self.inner, MACH_PORT_RIGHT_SEND, 1) };
        Self { inner: self.inner }
    }
}

impl Deref for TaskPort {
    type Target = mach_port_t;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Drop for TaskPort {
    fn drop(&mut self) {
        unsafe {
            // Decrements port refcount, doesn't deallocate unless refcount is 0
            mach_port_deallocate(mach_task_self(), self.inner);
        }
    }
}

impl TryFrom<mach_port_t> for TaskPort {
    type Error = std::io::Error;

    fn try_from(value: mach_port_t) -> Result<Self, Self::Error> {
        unsafe {
            mach_try!(mach_port_mod_refs(
                mach_task_self(),
                value,
                MACH_PORT_RIGHT_SEND,
                1
            ))?
        };
        Ok(Self { inner: value })
    }
}

impl TaskPort {
    /// "Moves" the given port into the wrapper struct (does not increment refcount) without checking
    /// validity
    /// # Safety
    /// The provided port name must map to a valid send right. Additionally, if the caller continues
    /// using the given raw port, the caller must manually increment its mach refcount.
    unsafe fn move_from(value: mach_port_t) -> Self {
        Self { inner: value }
    }
}
