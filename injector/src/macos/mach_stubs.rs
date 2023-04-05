#![allow(non_camel_case_types)]
#![allow(dead_code)]

/// C-defs until mach2 is updated to support these APIs

pub mod ldsyms {
    //! This module corresponds to `mach-o/ldsyms.h`
    use libc::{c_char, c_ulong, cpu_subtype_t, cpu_type_t};

    #[allow(dead_code)]
    #[repr(C)]
    pub struct mach_header_64 {
        pub magic: u32,
        pub cputype: cpu_type_t,
        pub cpusubtype: cpu_subtype_t,
        pub filetype: u32,
        pub ncmds: u32,
        pub sizeofcmds: u32,
        pub flags: u32,
        pub reserved: u32,
    }

    #[allow(dead_code)]
    #[repr(C)]
    pub struct mach_header {
        pub magic: u32,
        pub cputype: cpu_type_t,
        pub cpusubtype: cpu_subtype_t,
        pub filetype: u32,
        pub ncmds: u32,
        pub sizeofcmds: u32,
        pub flags: u32,
    }

    #[cfg(target_pointer_width = "64")]
    pub type mach_header_t = mach_header_64;
    #[cfg(not(target_pointer_width = "64"))]
    pub type mach_header_t = mach_header;

    extern "C" {
        pub static _mh_execute_header: mach_header_t;

        pub fn getsectiondata(
            mhp: *const mach_header_t,
            segname: *const c_char,
            sectname: *const c_char,
            size: *mut c_ulong,
        ) -> *mut u8;
    }
}

pub mod mach_error {
    use libc::c_char;

    use mach2::kern_return::kern_return_t;

    pub type mach_error_t = kern_return_t;
    extern "C" {
        pub fn mach_error_string(err: mach_error_t) -> *const c_char;
    }
}

pub mod machine {
    use libc::cpu_type_t;

    pub const CPU_ARCH_ABI64: cpu_type_t = 0x01000000;

    pub const CPU_TYPE_ANY: cpu_type_t = -1;

    pub const CPU_TYPE_X86: cpu_type_t = 7;
    pub const CPU_TYPE_X86_64: cpu_type_t = CPU_TYPE_X86 | CPU_ARCH_ABI64;

    pub const CPU_TYPE_ARM: cpu_type_t = 12;
    pub const CPU_TYPE_ARM64: cpu_type_t = CPU_TYPE_ARM | CPU_ARCH_ABI64;
}

pub mod proc {
    use libc::c_int;

    pub const P_TRANSLATED: c_int = 0x20000;
}

pub mod structs {
    //! This module corresponds to `mach/_structs.h`.

    use mach2::message::mach_msg_type_number_t;
    use std::mem;

    #[repr(C)]
    #[derive(Copy, Clone, Debug, Default, Hash, PartialOrd, PartialEq, Eq, Ord)]
    pub struct x86_thread_state32_t {
        pub __eax: u32,
        pub __ebx: u32,
        pub __ecx: u32,
        pub __edx: u32,
        pub __edi: u32,
        pub __esi: u32,
        pub __ebp: u32,
        pub __esp: u32,
        pub __ss: u32,
        pub __eflags: u32,
        pub __eip: u32,
        pub __cs: u32,
        pub __ds: u32,
        pub __es: u32,
        pub __fs: u32,
        pub __gs: u32,
    }

    impl x86_thread_state32_t {
        pub fn count() -> mach_msg_type_number_t {
            (mem::size_of::<Self>() / mem::size_of::<libc::c_int>()) as mach_msg_type_number_t
        }
    }

    #[repr(C)]
    #[derive(Copy, Clone, Debug, Default, Hash, PartialOrd, PartialEq, Eq, Ord)]
    pub struct arm_thread_state32_t {
        pub __r: [u32; 13],
        pub __sp: u32,
        pub __lr: u32,
        pub __pc: u32,
        pub __cpsr: u32,
    }

    impl arm_thread_state32_t {
        pub fn count() -> mach_msg_type_number_t {
            (mem::size_of::<Self>() / mem::size_of::<libc::c_int>()) as mach_msg_type_number_t
        }
    }

    pub const __DARWIN_ARM_THREAD_STATE64_FLAGS_NO_PTRAUTH: u32 = 0x1;
    // TODO add proper initialization with ptr-auth
    // for now just set flags to __DARWIN_ARM_THREAD_STATE64_FLAGS_NO_PTRAUTH
    #[repr(C)]
    #[derive(Copy, Clone, Debug, Default, Hash, PartialOrd, PartialEq, Eq, Ord)]
    pub struct arm_thread_state64_t {
        pub __x: [u64; 29],
        pub __fp: u64,
        pub __lr: u64,
        pub __sp: u64,
        pub __pc: u64,
        pub __cpsr: u32,
        pub __flags: u32,
    }

    impl arm_thread_state64_t {
        pub fn count() -> mach_msg_type_number_t {
            (mem::size_of::<Self>() / mem::size_of::<libc::c_int>()) as mach_msg_type_number_t
        }
    }
}

pub mod sysctl {
    // Generated with c2rust and cleaned up by hand

    use libc::{
        boolean_t, c_char, c_int, c_short, c_uchar, c_uint, c_ushort, c_void, dev_t, gid_t,
        itimerval, pid_t, sigset_t, timeval, uid_t,
    };

    pub const CTL_MAXNAME: usize = 12;

    extern "C" {
        pub type ucred;
        pub type session;
        pub type pgrp;
        pub type proc_0;
        pub type rusage;
        pub type user;
        pub type vnode;
        pub type sigacts;
    }

    pub type segsz_t = i32;
    pub type caddr_t = *mut c_char;
    pub type fixpt_t = u32;

    #[derive(Copy, Clone)]
    #[repr(C)]
    pub struct vmspace {
        pub dummy: i32,
        pub dummy2: caddr_t,
        pub dummy3: [i32; 5],
        pub dummy4: [caddr_t; 3],
    }
    #[derive(Copy, Clone)]
    #[repr(C)]
    pub union proc_list_timeval {
        pub p_st1: proc_list_links,
        pub __p_starttime: timeval,
    }
    #[derive(Copy, Clone)]
    #[repr(C)]
    pub struct proc_list_links {
        pub __p_forw: *mut proc_0,
        pub __p_back: *mut proc_0,
    }
    #[derive(Copy, Clone)]
    #[repr(C)]
    pub struct _pcred {
        pub pc_lock: [c_char; 72],
        pub pc_ucred: *mut ucred,
        pub p_ruid: uid_t,
        pub p_svuid: uid_t,
        pub p_rgid: gid_t,
        pub p_svgid: gid_t,
        pub p_refcnt: c_int,
    }
    #[derive(Copy, Clone)]
    #[repr(C)]
    pub struct _ucred {
        pub cr_ref: i32,
        pub cr_uid: uid_t,
        pub cr_ngroups: c_short,
        pub cr_groups: [gid_t; 16],
    }
    #[derive(Copy, Clone)]
    #[repr(C)]
    pub struct extern_proc {
        pub p_un: proc_list_timeval,
        pub p_vmspace: *mut vmspace,
        pub p_sigacts: *mut sigacts,
        pub p_flag: c_int,
        pub p_stat: c_char,
        pub p_pid: pid_t,
        pub p_oppid: pid_t,
        pub p_dupfd: c_int,
        pub user_stack: caddr_t,
        pub exit_thread: *mut c_void,
        pub p_debugger: c_int,
        pub sigwait: boolean_t,
        pub p_estcpu: c_uint,
        pub p_cpticks: c_int,
        pub p_pctcpu: fixpt_t,
        pub p_wchan: *mut c_void,
        pub p_wmesg: *mut c_char,
        pub p_swtime: c_uint,
        pub p_slptime: c_uint,
        pub p_realtimer: itimerval,
        pub p_rtime: timeval,
        pub p_uticks: u64,
        pub p_sticks: u64,
        pub p_iticks: u64,
        pub p_traceflag: c_int,
        pub p_tracep: *mut vnode,
        pub p_siglist: c_int,
        pub p_textvp: *mut vnode,
        pub p_holdcnt: c_int,
        pub p_sigmask: sigset_t,
        pub p_sigignore: sigset_t,
        pub p_sigcatch: sigset_t,
        pub p_priority: c_uchar,
        pub p_usrpri: c_uchar,
        pub p_nice: c_char,
        pub p_comm: [c_char; 17],
        pub p_pgrp: *mut pgrp,
        pub p_addr: *mut user,
        pub p_xstat: c_ushort,
        pub p_acflag: c_ushort,
        pub p_ru: *mut rusage,
    }
    #[derive(Copy, Clone)]
    #[repr(C)]
    pub struct eproc {
        pub e_paddr: *mut proc_0,
        pub e_sess: *mut session,
        pub e_pcred: _pcred,
        pub e_ucred: _ucred,
        pub e_vm: vmspace,
        pub e_ppid: pid_t,
        pub e_pgid: pid_t,
        pub e_jobc: c_short,
        pub e_tdev: dev_t,
        pub e_tpgid: pid_t,
        pub e_tsess: *mut session,
        pub e_wmesg: [c_char; 8],
        pub e_xsize: segsz_t,
        pub e_xrssize: c_short,
        pub e_xccount: c_short,
        pub e_xswrss: c_short,
        pub e_flag: i32,
        pub e_login: [c_char; 12],
        pub e_spare: [i32; 4],
    }
    #[derive(Copy, Clone)]
    #[repr(C)]
    pub struct kinfo_proc {
        pub kp_proc: extern_proc,
        pub kp_eproc: eproc,
    }
}

pub mod tasks {
    //! This module corresponds to mach/task.defs.

    use mach2::kern_return::kern_return_t;
    use mach2::mach_types::{task_t, thread_act_t};
    use mach2::message::mach_msg_type_number_t;
    use mach2::thread_status::{thread_state_flavor_t, thread_state_t};

    extern "C" {
        pub fn thread_create_running(
            parent_task: task_t,
            flavor: thread_state_flavor_t,
            state: thread_state_t,
            state_size: mach_msg_type_number_t,
            child_thread: *mut thread_act_t,
        ) -> kern_return_t;
    }
}

pub mod thread_act {
    //! This module corresponds to `mach/thread_act.defs`.

    use mach2::kern_return::kern_return_t;
    use mach2::mach_types::thread_act_t;

    extern "C" {
        pub fn thread_terminate(thread: thread_act_t) -> kern_return_t;
    }
}

pub mod thread_status {
    #![allow(dead_code)]

    use mach2::thread_status::thread_state_flavor_t;

    pub static ARM_THREAD_STATE64: thread_state_flavor_t = 6;
    pub static ARM_THREAD_STATE32: thread_state_flavor_t = 9;
}

pub mod traps {
    //! This module corresponds to `mach/mach_traps.h`.

    use libc::{c_int, c_void};

    use mach2::kern_return::kern_return_t;
    use mach2::mach_types::task_t;

    extern "C" {
        pub fn pid_for_task(task: task_t, pid: *mut c_int) -> kern_return_t;

        pub fn _thread_set_tsd_base(base: *mut c_void);
    }
}
