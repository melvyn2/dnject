#![allow(non_camel_case_types)]

// This file holds the code that is ran in the targeted process to load the desired code objects
// Because the raw shellcode of the final functions are injected, these functions cannot use relocations
// to link to other functions. Function pointers are provided by the injector instead.
// Functions called here cannot be allowed to panic

// IMPORTANT (and probably TODO) when left unoptimized and with debug-assertions enabled,
// shellcode calls stdlib functions and uses relocations. In other words, either of opt-level = 0
// or debug-assertions = true will make this just fail (optimize attributes do not apply when opt-level = 0)
// It seems like opt-level >= 2 is required on x86 (32-bit), even though the optimize attributes
// should override any non-zero value

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::intrinsics::unreachable;
use core::mem::transmute;
use core::ptr::{null, null_mut};
use core::sync::atomic::{fence, AtomicU8, Ordering};
use std::intrinsics::atomic_store_release;
use std::ptr::addr_of_mut;

// Manually use libc types to avoid linking to libc
pub(crate) type pthread_routine_t = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
pub(crate) type pthread_t = usize;

pub(crate) type kern_return_t = c_int;
pub(crate) type mach_port_t = c_uint;
pub(crate) type thread_act_t = mach_port_t;

const RTLD_NOW: c_int = 0x2;

pub(crate) struct RemoteThreadData {
    // These should really be atomic...
    // 0 = Not started, 1 = started, 2 = pthread_create failed, 3 = pthread_create successful
    pub bootstrap_status: AtomicU8,
    // 0 = Not started, 1 = started, 2 = dlopen errored, 3 = finished
    pub loader_status: AtomicU8,

    // Use bottom of stack allocation for TLS base for boostrap thread
    pub tsd_base: *mut c_void,

    // Bootstrap thread fn pointers
    pub pthread_create_from_mach_thread: unsafe extern "C" fn(
        *mut pthread_t,
        *const c_void,
        pthread_routine_t,
        *mut c_void,
    ) -> c_int,
    // Fn Pointer to inj_loop
    pub pthread_entrypoint: pthread_routine_t,
    pub thread_set_tsd_base: unsafe extern "C" fn(*mut c_void),
    pub mach_thread_self: unsafe extern "C" fn() -> mach_port_t,
    pub thread_terminate: unsafe extern "C" fn(thread_act_t) -> kern_return_t,

    // Loader thread fn pointers
    pub dlopen: unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void,
    pub dlerror: unsafe extern "C" fn() -> *mut c_char,
    pub pthread_exit: unsafe extern "C" fn(*mut c_void) -> !,

    // C string pointers to the paths of the injected libraries
    // Overwritten with module handles on `dlopen` success
    pub lib_ptrs: [*const c_char; u8::MAX as usize],

    // dlerror string set on loader failure
    pub dlerror_str: [u8; 1024],
}

// Put all shellcode into its own segment. Sections aren't guaranteed to be page-aligned,
// which we need; segments are, so we use are own.
// Important! linker needs `-segprot __SHELLCODE rx rx`

// Different entrypoint symbols which inline the real code are used to select the right calling
// convention; these are selected so that a register can be used to pass in the pointer to the
// mega-struct, rather than having to mess with the stack.

#[cfg(target_arch = "x86_64")]
#[optimize(speed)]
#[link_section = "__SHELLCODE,__inj_bootstrap"]
pub(crate) unsafe extern "sysv64" fn bootstrap_entry(args: *mut RemoteThreadData) -> ! {
    pthread_bootstrap(args)
}

#[cfg(target_arch = "x86")]
#[optimize(speed)]
#[link_section = "__SHELLCODE,__inj_bootstrap"]
pub(crate) unsafe extern "fastcall" fn bootstrap_entry(args: *mut RemoteThreadData) -> ! {
    pthread_bootstrap(args)
}

#[cfg(target_arch = "aarch64")]
#[optimize(speed)]
#[link_section = "__SHELLCODE,__inj_bootstrap"]
pub(crate) unsafe extern "C" fn bootstrap_entry(args: *mut RemoteThreadData) -> ! {
    pthread_bootstrap(args)
}

// Optimize for speed to encourage inlining
#[optimize(speed)]
#[inline(always)]
#[link_section = "__SHELLCODE,__inj_bootstrap"]
unsafe fn pthread_bootstrap(args_ptr: *mut RemoteThreadData) -> ! {
    // Tell injector that bootstrap has started
    // Avoid calling AtomicU8::store as it gets linked in
    // atomic_store_release(addr_of_mut!((*args_ptr).bootstrap_status) as *mut u8, 1);
    atomic_store_release((*args_ptr).bootstrap_status.as_ptr(), 1);

    let mut loader_thread: pthread_t = 0;
    // Spawn a new pthread, because we're in a "half-thread" that only exists in the mach interfaces
    // but not BSD/pthread, and dlopen relies on being in a pthread
    // This new pthread will then run the actual dlopen loop
    if ((*args_ptr).pthread_create_from_mach_thread)(
        &mut loader_thread,
        null(),
        (*args_ptr).pthread_entrypoint,
        args_ptr as *mut c_void,
    ) == 0
    {
        // atomic_store_release(addr_of_mut!((*args_ptr).loader_status) as *mut u8, 3);
        atomic_store_release((*args_ptr).bootstrap_status.as_ptr(), 3); // Success
    } else {
        atomic_store_release(addr_of_mut!((*args_ptr).loader_status) as *mut u8, 2);
        atomic_store_release((*args_ptr).bootstrap_status.as_ptr(), 2); // Failure :(
    }

    // `thread_terminate` calls `mig_get_reply_port` which relies at least some semblance of TLS
    // We don't need to set up a full pthread struct for this, just having valid allocated zeroes
    // is enough to not completely crash the whole process
    // (if the reply port slot is zero, `mig_get_reply_port constructs one)
    ((*args_ptr).thread_set_tsd_base)((*args_ptr).tsd_base);
    // Now we can gtfo
    ((*args_ptr).thread_terminate)(((*args_ptr).mach_thread_self)());
    // on x86_64, emits instruction `ud2` to crash if things really go wrong
    unreachable()
}

#[optimize(speed)]
#[link_section = "__SHELLCODE,__inj_bootstrap"]
pub(crate) unsafe fn inj_loop(args_ptr: *mut c_void) -> *const c_void {
    // SAFETY: `pthread_create` allows one argument, defined as *mut c_void, but doesn't care what it is
    // so we only leave the signature as so for conformance; the only caller should be the boostrap
    // which knows what this pointer should actually be
    let args_ptr = transmute::<*mut c_void, *mut RemoteThreadData>(args_ptr);

    // Tell the injector that loader thread has launched
    // atomic_store_release(addr_of_mut!((*args_ptr).loader_status) as *mut u8, 1);
    atomic_store_release((*args_ptr).loader_status.as_ptr(), 1);

    // Manually index into slice to avoid calling/linking get_mut_unchecked
    let mut lib_str_ptr: *mut *const c_char = (*args_ptr).lib_ptrs.as_mut_ptr();

    // Avoid calling is_null() as it gets linked in
    #[allow(clippy::cmp_null)]
    while (*lib_str_ptr) != null() {
        let ret = ((*args_ptr).dlopen)(*lib_str_ptr, RTLD_NOW);
        // Re-use the array of string ptrs as an array of module handles
        *lib_str_ptr = ret as *const c_char;

        if ret == null_mut() {
            // Try to send back dlerror if it exists
            let dlerror_ptr = ((*args_ptr).dlerror)();
            if dlerror_ptr != null_mut() {
                cstr_copy(dlerror_ptr, &mut (*args_ptr).dlerror_str);
            }

            // atomic_store_release(addr_of_mut!((*args_ptr).loader_status) as *mut u8, 2);
            atomic_store_release((*args_ptr).loader_status.as_ptr(), 2);

            pthread_exit_trap(args_ptr)
        }

        lib_str_ptr = lib_str_ptr.add(1);
    }

    // Tell injector that loader thread is done
    // atomic_store_release(addr_of_mut!((*args_ptr).loader_status) as *mut u8, 3);
    atomic_store_release((*args_ptr).loader_status.as_ptr(), 3);

    pthread_exit_trap(args_ptr)
}

// Reimplement strncpy (but better)
// Takes a rust fat pointer of bytes and copies in the C string, truncating to the slice length
// while ensuring a nul terminator exists
#[optimize(speed)]
#[link_section = "__SHELLCODE,__inj_bootstrap"]
unsafe fn cstr_copy(cstr: *mut c_char, buf: &mut [u8]) {
    let mut idx = 0;
    while (idx < buf.len() - 1) && (*(cstr.add(idx)) != 0) {
        buf.as_mut_ptr().add(idx).write(*(cstr.add(idx)) as u8);
        idx += 1;
    }
    // Enforce terminating nul
    buf.as_mut_ptr().add(idx).write(0);
}

// Force compiler to emit unreachable trap (`ud2` instruction on x86_64) after pthread_exit
// to help disassembly and emit memory fence before exit
#[inline(always)]
#[optimize(size)]
#[link_section = "__SHELLCODE,__inj_bootstrap"]
unsafe fn pthread_exit_trap(args: *const RemoteThreadData) -> ! {
    // Ensure mem is fully synced before exit
    fence(Ordering::SeqCst);
    // SAFETY: transmute return value from `!` to `()` to force compiler to emit following unreachable trap
    let pthread_exit: unsafe extern "C" fn(*mut c_void) =
        transmute((*args).pthread_exit as *const c_void);
    pthread_exit(null_mut());
    unreachable()
}
