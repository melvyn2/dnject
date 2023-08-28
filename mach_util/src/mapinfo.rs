// from lsof

use std::io::ErrorKind;
use std::mem::{size_of, MaybeUninit};

use libc::{c_int, c_void, pid_t, proc_pidinfo, vnode_info_path};

const PROC_PIDREGIONPATHINFO: c_int = 8;
const PROC_PIDREGIONPATHINFO_SIZE: c_int = size_of::<proc_regionwithpathinfo>() as c_int;

pub fn mem_regions_for_pid(pid: pid_t) -> Result<Vec<proc_regionwithpathinfo>, std::io::Error> {
    let mut r = vec![];
    let mut addr: u64 = 0;
    loop {
        let mut reg: MaybeUninit<proc_regionwithpathinfo> = MaybeUninit::zeroed();
        let written = unsafe {
            proc_pidinfo(
                pid,
                PROC_PIDREGIONPATHINFO,
                addr,
                reg.as_mut_ptr() as *mut c_void,
                PROC_PIDREGIONPATHINFO_SIZE,
            )
        };
        if written <= 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ESRCH) || err.raw_os_error() == Some(libc::EINVAL) {
                break;
            }
            return Err(err);
        }
        if written < PROC_PIDREGIONPATHINFO_SIZE {
            return Err(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                format!(
                    "only recieved {}/{} bytes of struct",
                    written, PROC_PIDREGIONPATHINFO_SIZE
                ),
            ));
        }
        let reg = unsafe { reg.assume_init() };
        addr = reg.prp_prinfo.pri_address + reg.prp_prinfo.pri_size;
        r.push(reg);
    }
    Ok(r)
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct proc_regionwithpathinfo {
    pub prp_prinfo: proc_regioninfo,
    pub prp_vip: vnode_info_path,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug)]
pub struct proc_regioninfo {
    pub pri_protection: u32,
    pub pri_max_protection: u32,
    pub pri_inheritance: u32,
    pub pri_flags: u32,
    pub pri_offset: u64,
    pub pri_behavior: u32,
    pub pri_user_wired_count: u32,
    pub pri_user_tag: u32,
    pub pri_pages_resident: u32,
    pub pri_pages_shared_now_private: u32,
    pub pri_pages_swapped_out: u32,
    pub pri_pages_dirtied: u32,
    pub pri_ref_count: u32,
    pub pri_shadow_depth: u32,
    pub pri_share_mode: u32,
    pub pri_private_pages_resident: u32,
    pub pri_shared_pages_resident: u32,
    pub pri_obj_id: u32,
    pub pri_depth: u32,
    pub pri_address: u64,
    pub pri_size: u64,
}
