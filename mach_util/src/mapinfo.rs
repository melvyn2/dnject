use std::ffi::{c_void, CStr, OsString};
use std::io::ErrorKind;
use std::mem::{size_of, MaybeUninit};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::ptr::addr_of_mut;

use libc::{c_int, pid_t, proc_pidinfo, proc_regionfilename, PROC_PIDPATHINFO_MAXSIZE};

use mach2::mach_types::vm_task_entry_t;
use mach2::message::mach_msg_type_number_t;
use mach2::port::mach_port_name_t;
use mach2::vm::mach_vm_region;
use mach2::vm_region::{vm_region_basic_info_data_64_t, vm_region_info_t, VM_REGION_BASIC_INFO_64};
use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t};

use crate::error::MachError;
use crate::mach_try;
use crate::traps::pid_for_task;

#[derive(Debug, Clone)]
pub struct Region {
    size: mach_vm_size_t,
    info: vm_region_basic_info_data_64_t,
    address: mach_vm_address_t,
    filename: Option<PathBuf>,
}

impl Region {
    pub fn end(&self) -> mach_vm_address_t {
        self.address + self.size as mach_vm_address_t
    }

    pub fn is_read(&self) -> bool {
        self.info.protection & mach2::vm_prot::VM_PROT_READ != 0
    }
    pub fn is_write(&self) -> bool {
        self.info.protection & mach2::vm_prot::VM_PROT_WRITE != 0
    }
    pub fn is_exec(&self) -> bool {
        self.info.protection & mach2::vm_prot::VM_PROT_EXECUTE != 0
    }

    pub fn filename(&self) -> Option<&PathBuf> {
        self.filename.as_ref()
    }
}

pub fn task_mem_regions(task: mach_port_name_t) -> Result<Vec<Region>, MachError> {
    let pid = unsafe {
        let mut pid = 0;
        mach_try!(pid_for_task(task, addr_of_mut!(pid)))?;
        pid
    };

    dbg!(pid);

    let mut vec = vec![];
    let mut prev_reg = region_for_addr(task, Some(pid), 1).unwrap();
    vec.push(prev_reg.clone());
    loop {
        match region_for_addr(task, Some(pid), prev_reg.end() + 1) {
            Ok(new_reg) => {
                vec.push(new_reg.clone());
                prev_reg = new_reg;
            }
            _ => return Ok(vec),
        }
    }
}

pub fn region_for_addr(
    target_task: mach_port_name_t,
    pid: Option<pid_t>,
    mut address: mach_vm_address_t,
) -> Result<Region, MachError> {
    // TODO says 64 but might work on i686 procs
    let (info, size): (vm_region_basic_info_data_64_t, mach_vm_size_t) = unsafe {
        let mut r_info = MaybeUninit::zeroed();
        let mut r_size: mach_vm_size_t = u64::MAX;
        let mut count = size_of::<vm_region_basic_info_data_64_t>() as mach_msg_type_number_t;
        let mut object_name = 0; // Unused

        mach_try!(mach_vm_region(
            target_task as vm_task_entry_t,
            &mut address,
            &mut r_size,
            VM_REGION_BASIC_INFO_64,
            r_info.as_mut_ptr() as vm_region_info_t,
            &mut count,
            &mut object_name,
        ))?;
        assert_ne!(r_size, 0);
        (r_info.assume_init(), r_size)
    };

    let filename = pid.and_then(|p| region_filename(p, address).ok());

    Ok(Region {
        size,
        info,
        address,
        filename,
    })
}

pub fn region_filename(pid: i32, address: u64) -> Result<PathBuf, std::io::Error> {
    let mut buf: Vec<u8> = Vec::with_capacity(PROC_PIDPATHINFO_MAXSIZE as usize);

    let ret = unsafe {
        proc_regionfilename(
            pid,
            address,
            buf.as_mut_ptr() as *mut c_void,
            buf.capacity() as u32,
        )
    };

    if ret > 0 {
        unsafe {
            buf.set_len(ret as usize);
        }
        Ok(PathBuf::from(OsString::from_vec(buf)))
    } else {
        return Err(std::io::Error::new(
            std::io::Error::last_os_error().kind(),
            format!(
                "failed to find region name for addr 0x{:x} for pid {}",
                address, pid
            ),
        ));
    }
}
