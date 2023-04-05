use std::ops::Deref;
use std::rc::Rc;

use mach2::mach_port::mach_port_deallocate;
use mach2::port::mach_port_t;
use mach2::traps::mach_task_self;

/// A reference-counted wrapper struct for [mach_port_t], to allow deallocation on drop
#[derive(Clone)]
pub struct TaskPort {
    inner: Rc<mach_port_t>,
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
            mach_port_deallocate(mach_task_self(), *self.inner);
        }
    }
}

impl TaskPort {
    /// # Safety
    /// Caller must ensure that the given [mach_port_t] is unique (the only used copy), to avoid
    /// deallocation during use if the created struct is dropped while the port is in use elsewhere,
    /// and the inverse.
    pub unsafe fn from(value: mach_port_t) -> Self {
        Self {
            inner: Rc::new(value),
        }
    }
}
