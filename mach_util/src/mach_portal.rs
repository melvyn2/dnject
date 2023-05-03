use libc::pid_t;
use mach2::bootstrap::bootstrap_look_up;
use mach2::mach_port::{mach_port_allocate, mach_port_deallocate, mach_port_insert_right};
use std::ffi::CString;
use std::io::ErrorKind;
use std::mem;
use std::mem::MaybeUninit;
use std::ptr::addr_of_mut;

use crate::bsm::audit_token_to_pid;
use mach2::message::{
    mach_msg, mach_msg_body_t, mach_msg_header_t, mach_msg_port_descriptor_t,
    MACH_MSGH_BITS_COMPLEX, MACH_MSG_TIMEOUT_NONE, MACH_MSG_TYPE_COPY_SEND,
    MACH_MSG_TYPE_MAKE_SEND, MACH_RCV_MSG, MACH_SEND_MSG,
};
use mach2::port::{mach_port_t, MACH_PORT_NULL, MACH_PORT_RIGHT_RECEIVE};
use mach2::task::{task_get_special_port, TASK_BOOTSTRAP_PORT};
use mach2::traps::mach_task_self;

use crate::mach_try;
use crate::message::{
    mach_msg_recv_t, mach_msg_send_t, MACH_MSGH_BITS_REMOTE, MACH_RCV_TRAILER_AUDIT,
    MACH_RCV_TRAILER_ELEMENTS, MACH_RCV_TRAILER_TYPE,
};
use crate::private::bootstrap_register2;

#[must_use]
pub struct MachPortal {
    server_port: mach_port_t,
    bootstrap_name: String,
}

impl MachPortal {
    /// Create a new mach port registered with the given bootstrap name
    pub fn register(bootstrap_name: &str) -> Result<Self, std::io::Error> {
        let port = unsafe {
            let port: mach_port_t = {
                let mut r = 0;
                mach_try!(mach_port_allocate(
                    mach_task_self(),
                    MACH_PORT_RIGHT_RECEIVE,
                    addr_of_mut!(r)
                ))?;
                r
            };

            // Allocate a send right for the server port.
            mach_try!(mach_port_insert_right(
                mach_task_self(),
                port,
                port,
                MACH_MSG_TYPE_MAKE_SEND
            ))?;
            port
        };

        let name = CString::new(bootstrap_name)?;
        unsafe {
            let bootstrap_port: mach_port_t = {
                let mut r = MaybeUninit::zeroed();
                mach_try!(task_get_special_port(
                    mach_task_self(),
                    TASK_BOOTSTRAP_PORT,
                    r.as_mut_ptr()
                ))?;
                r.assume_init()
            };
            mach_try!(bootstrap_register2(bootstrap_port, name.as_ptr(), port, 0))?;
        }

        Ok(Self {
            server_port: port,
            bootstrap_name: bootstrap_name.to_string(),
        })
    }

    /// Create a new mach port connected to the bootstrap port at the given name
    pub fn connect(bootstrap_name: &str) -> Result<Self, std::io::Error> {
        let bootstrap_port: mach_port_t = unsafe {
            let mut r = 0;
            mach_try!(task_get_special_port(
                mach_task_self(),
                TASK_BOOTSTRAP_PORT,
                addr_of_mut!(r)
            ))?;
            r
        };

        let name = CString::new(bootstrap_name)?;
        let server_port: mach_port_t = unsafe {
            let mut r = 0;
            mach_try!(bootstrap_look_up(
                bootstrap_port,
                name.as_ptr(),
                addr_of_mut!(r)
            ))?;
            r
        };

        Ok(Self {
            server_port,
            bootstrap_name: bootstrap_name.to_string(),
        })
    }

    /// Send a mach port through this port
    pub fn send_port(self, port: mach_port_t) -> Result<(), std::io::Error> {
        let mut msg = mach_msg_send_t {
            msg_header: mach_msg_header_t {
                msgh_bits: MACH_MSGH_BITS_REMOTE(MACH_MSG_TYPE_COPY_SEND) | MACH_MSGH_BITS_COMPLEX,
                msgh_size: mem::size_of::<mach_msg_send_t>() as u32,
                msgh_remote_port: self.server_port,
                msgh_local_port: MACH_PORT_NULL,
                msgh_voucher_port: MACH_PORT_NULL,
                msgh_id: 0,
            },
            msg_body: mach_msg_body_t {
                msgh_descriptor_count: 1,
            },
            task_port: mach_msg_port_descriptor_t::new(port, MACH_MSG_TYPE_COPY_SEND),
        };
        unsafe {
            mach_try!(mach_msg(
                &mut msg.msg_header,
                MACH_SEND_MSG,
                mem::size_of::<mach_msg_send_t>() as u32,
                0,
                MACH_PORT_NULL,
                MACH_MSG_TIMEOUT_NONE,
                MACH_PORT_NULL
            ))?
        };
        Ok(())
    }

    /// Block on and receive a mach port through this port
    pub fn receive_port(self, pid: Option<pid_t>) -> Result<mach_port_t, std::io::Error> {
        let msg: mach_msg_recv_t = unsafe {
            let mut r: MaybeUninit<mach_msg_recv_t> = MaybeUninit::zeroed();
            mach_try!(mach_msg(
                std::ptr::addr_of_mut!((*r.as_mut_ptr()).msg_header),
                MACH_RCV_MSG
                    | MACH_RCV_TRAILER_TYPE(MACH_RCV_TRAILER_AUDIT)
                    | MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT),
                0,
                mem::size_of::<mach_msg_recv_t>() as u32,
                self.server_port,
                100, // 100 ms timeout
                MACH_PORT_NULL
            ))?;
            r.assume_init()
        };

        // Check that the message was send by the child
        if let Some(check_pid) = pid {
            unsafe {
                if audit_token_to_pid(msg.msg_trailer.msgh_audit) != check_pid as u32 {
                    return Err(std::io::Error::new(
                        ErrorKind::Other,
                        format!(
                            "expected task port for child pid {}, got pid {} instead",
                            check_pid,
                            audit_token_to_pid(msg.msg_trailer.msgh_audit)
                        ),
                    ));
                }
            }
        }

        Ok(msg.task_port.name)
    }
}

impl Drop for MachPortal {
    fn drop(&mut self) {
        // Nothing to do if we fail, ignore return value
        unsafe {
            mach_port_deallocate(mach_task_self(), self.server_port);
        }
    }
}
