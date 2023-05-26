use std::alloc::{Allocator, Global, Layout};
use std::ffi::{c_char, c_int, c_ulong, c_void, CStr, CString};
use std::mem::size_of;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::ptr::{addr_of, addr_of_mut, copy_nonoverlapping, null};
use std::sync::atomic::{fence, AtomicU8, Ordering};
use std::thread::sleep;
use std::time::Duration;

use libc::{kill, pid_t, SIGKILL, _SC_PAGESIZE};

use mach2::boolean::boolean_t;
use mach2::mach_port::mach_port_deallocate;
use mach2::port::mach_port_t;
use mach2::thread_status::thread_state_t;
use mach2::traps::{mach_task_self, task_for_pid};
use mach2::vm::{mach_vm_allocate, mach_vm_deallocate, mach_vm_remap};
use mach2::vm_inherit::VM_INHERIT_SHARE;
use mach2::vm_prot::{VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE};
use mach2::vm_statistics::VM_FLAGS_ANYWHERE;
use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t};

use crate::{InjectorError, InjectorErrorKind};
use mach_util::ldsyms::{_mh_execute_header, getsectiondata};
use mach_util::mach_error::mach_error_string;
use mach_util::tasks::thread_create_running;
use mach_util::thread_act::thread_terminate;
use mach_util::traps::pid_for_task;
use mach_util::{get_pid_cpu_type, mach_try};

mod bootstrap;

fn ensure_matching_arch(target: pid_t) -> Result<(), InjectorError> {
    let target_arch = get_pid_cpu_type(target)?;
    let self_arch = unsafe { _mh_execute_header.cputype };
    if target_arch != self_arch {
        // TODO translate CPU type number to string
        return Err(InjectorError::new(
            InjectorErrorKind::InvalidArchitecture,
            format!(
                "target has different CPU type ({:x}) than injector ({:x})",
                target_arch, self_arch
            ),
        ));
    };
    Ok(())
}

/// A handle to a native process which can be injected into
/// # Process
/// Injection on macOS happens in roughly 3 different phases:
/// 1. Acquire target task port
///     - A task port is a special mach port that the kernel listens to and allows the sender to modify
///       the mach task it targets. We can either acquire it by calling the [task_for_pid] trap, or
///       by spawning a child process, which sends the parent its mach port through the bootstrap port.
///       Unfortunately, the latter doesn't work when `exec`ing a new process, as old task ports are
///       closed. [new](Self::new) therefore just spawns a new process and calls [task_for_pid] on it.
/// 2. Run bootstrap code
///     - A mach thread is created in the target through the task port, running shellcode copied
///       from the injector. The created mach thread (bootstrap thread) spawns a full bsd/pthread
///       thread (loader thread).
/// 3. Load modules
///     - The loader thread then calls [dlopen](libc::dlopen) on all the requested modules.
// or [dlclose](libc::dlclose) when ejecting. (TODO)
/// # Codesigning and entitlements on macOS
/// Apple has gradually made interacting with foreign processes more difficult with each iteration of
/// macOS. Each of the above steps is affected:
/// 1. Task ports
///     - Starting with macOS 10.11, [task_for_pid] became restricted by SIP. One of the following
///       is required to successfully use the [task_for_pid] trap:
///       - SIP debugging protection is disabled
///       - the injecting process is ran as root and the target does not have the "hardened runtime"
///         codesigning flag
///       - the target is signed with `get-task-allow`
///         - When injecting into a target with the "hardened runtime" codesigning flag,
///           the host must also have `com.apple.security.cs.debugger`
///           (`task_for_pid-allow` on iOS)
///       - the host has the `com.apple.system-task-ports` or `platform-application` private
///         entitlements (only possible with exploit)
/// 2. Bootstrapping
///     - Pages are mapped directly from injector: this means they stay W^X and signed as they are
///       executed, so `com.apple.security.cs.allow-unsigned-executable-memory` and
///       `com.apple.security.cs.allow-jit` are *not* needed
/// 3. Loading
///     - The same restrictions on injected module loading apply as with normal module loading.
///       This means that when the target has the "hardened runtime" codesigning flag,
///       it must have the `com.apple.security.cs.disable-library-validation` entitlement unless:
///         - the injected dylib is signed with the same Team ID as the target library
///         - the injected dylib is signed as a platform binary (only possible with exploit)
// TODO if `com.apple.security.cs.allow-unsigned-executable-memory` is present but not
// `com.apple.security.cs.disable-library-validation`, we could probably manually map?
pub struct ProcHandle {
    pid: pid_t,
    task_port: mach_port_t,
    child_handle: Option<Child>,
    modules: Vec<ModHandle>,
}
pub type ModHandle = (PathBuf, *mut c_void);

impl TryFrom<pid_t> for ProcHandle {
    type Error = InjectorError;

    /// Attempt to gain access to the specified pid. See [Codesigning and entitlements on macOS](ProcHandle#codesigning-and-entitlements-on-macos)
    fn try_from(target: pid_t) -> Result<Self, Self::Error> {
        ensure_matching_arch(target)?;
        log::trace!("Validated matching target process architecture");

        let mut task_port: libc::mach_port_t = 0;
        match unsafe { task_for_pid(mach_task_self(), target, &mut task_port) } {
                libc::KERN_SUCCESS => Ok(()),
                libc::KERN_FAILURE => Err(InjectorError::new(InjectorErrorKind::AttachPermission,
      "task_for_pid returned KERN_FAILURE. \
            Ensure you have the proper permissions and check Console.app for `macOSTaskPolicy` entries.")),
                other => Err(InjectorError::new(InjectorErrorKind::AttachFailure,
                                    format!("`task_for_pid({})` returned unknown code 0x{:x}: {}",
                                            target, other,
                                            unsafe {CStr::from_ptr(mach_error_string(other))}.to_string_lossy())))
            }?;

        log::trace!(
            "Got task port name {} by task_for_pid for pid {}",
            task_port,
            target
        );

        Ok(Self {
            pid: target,
            task_port,
            child_handle: None,
            modules: vec![],
        })
    }
}

impl TryFrom<mach_port_t> for ProcHandle {
    type Error = InjectorError;

    /// Checks if the port is a valid task port and creates a new handle from it.
    ///
    /// This method has move semantics in regards to the mach port, as its refcount is not incremented.
    /// The callee must manually increment the refcount if it needs to continue using the port.
    fn try_from(task_port: mach_port_t) -> Result<Self, Self::Error> {
        let pid = unsafe {
            let mut pid = 0;
            mach_try!(pid_for_task(task_port, &mut pid))?;
            pid
        };

        // If `pid_for_task` succeeded, the port is a valid task port
        log::trace!(
            "Validated task port name {} for pid {} by pid_for_task",
            task_port,
            pid
        );

        Ok(Self {
            pid,
            task_port,
            child_handle: None,
            modules: vec![],
        })
    }
}

impl ProcHandle {
    /// Attempt to use an existing task port to gain access to a target
    /// # Safety
    /// Caller must ensure that the given `mach_port_t` is not in use elsewhere/is fully moved,
    /// to avoid deallocation during use by caller or struct. (See [TaskPort])

    /// Spawns a child process using `cmd`, retains the [Child] handle, and
    /// attempts to gain the task port with [task_for_pid]
    pub fn new(cmd: Command) -> Result<Self, InjectorError> {
        let mut cmd = cmd;
        let child = cmd.spawn()?;
        let mut res = Self::try_from(child.id() as pid_t)?;
        res.child_handle = Some(child);
        Ok(res)
    }

    /// Spawn a child process using `cmd`, and retain its task port to allow later
    /// injection or module manipulation
    #[cfg(feature = "test_broken")] // This is broken (seems like `exec` deletes task ports...)
    pub fn new_mpd(cmd: Command) -> Result<Self, Box<dyn std::error::Error>> {
        // Put imports here as to not trigger clippy when function is ignored
        use spawn_task_port::CommandSpawnWithTask;

        let mut cmd = cmd;
        let (child, task_port) = cmd.spawn_get_task_port()?;

        if log::max_level() == log::LevelFilter::Trace {
            log::trace!(
                "Spawned child with pid {} and task port name {}",
                child.id(),
                task_port
            );
        } else {
            log::info!("Spawned child with pid {}", child.id());
        }

        ensure_matching_arch(child.id() as pid_t)?;
        log::trace!("Validated matching child process architecture");

        // When child `exec`s new binary, this task port stops existing :(
        unsafe {
            let mut pid = 0;
            mach_try!(pid_for_task(task_port, &mut pid))?;
        };
        log::trace!(
            "Validated task port name {} for pid {} by pid_for_task",
            task_port,
            child.id()
        );

        Ok(ProcHandle {
            pid: child.id() as pid_t,
            task_port,
            child_handle: Some(child),
            modules: vec![],
        })
    }

    /// Works like [new](Self::new), but also loads the libraries at the given paths sequentially
    /// in the child process **before the target binary is executed (before `exec` is called)**.
    /// As with [inject](Self::inject), library paths are canonicalize before injection, so
    /// paths can be relative to the current working directory of the injector.
    #[cfg(feature = "test_broken")] // This is broken and useless
    pub fn new_pre_inject(
        cmd: Command,
        libs: &[PathBuf],
    ) -> Result<ProcHandle, Box<dyn std::error::Error>> {
        use libc::{MAP_ANONYMOUS, MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE, RTLD_NOW};
        use spawn_task_port::CommandSpawnWithTask;
        use std::cmp::min;
        use std::mem::MaybeUninit;
        use std::os::unix::process::CommandExt;
        use std::ptr::null_mut;

        if libs.len() >= u8::MAX as usize {
            return Err(Box::new(std::io::Error::new(
                ErrorKind::ArgumentListTooLong,
                format!(
                    "too many libraries for a single new_pre_inject call (max {})",
                    u8::MAX - 1
                ),
            )));
        }

        let mut cmd = cmd;

        struct SharedMem {
            // Tracks if child has written mem yet
            init: bool,
            successes: u8,
            handles: [*mut c_void; u8::MAX as usize],
            // Should be plenty, and keeps us under the common page size of 4096 bytes
            error_string: [u8; 2000],
        }
        impl SharedMem {
            fn page_rounded_size() -> usize {
                let pagesize = unsafe { libc::sysconf(_SC_PAGESIZE) } as usize;
                let unrounded_size = size_of::<Self>();
                unrounded_size + (pagesize - (unrounded_size % pagesize))
            }
        }

        let shared_map_ptr = unsafe {
            let mut source: SharedMem = MaybeUninit::zeroed().assume_init();
            source.init = false;
            let addr = libc::mmap(
                null_mut(),
                SharedMem::page_rounded_size(),
                PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_ANONYMOUS,
                -1,
                0,
            );
            if addr == MAP_FAILED {
                let mmap_err = std::io::Error::last_os_error();
                return Err(Box::new(std::io::Error::new(
                    mmap_err.kind(),
                    format!("mmap failed: {}", mmap_err),
                )));
            }
            let addr = addr as *mut SharedMem;
            std::ptr::write(addr, source);
            addr
        };
        log::trace!(
            "Allocated shared preinject struct at {:x} ({} bytes)",
            shared_map_ptr as u64,
            SharedMem::page_rounded_size()
        );

        let libs_cstr: Vec<CString> = libs
            .iter()
            .cloned()
            .map(|path| Ok(CString::new(path.canonicalize()?.as_os_str().as_bytes()).unwrap()))
            .collect::<Result<Vec<CString>, std::io::Error>>()?;

        // Pass usize to bypass pointer thread-safety checks
        let shared_map_ptr_for_target = shared_map_ptr as usize;
        unsafe {
            cmd.pre_exec(move || {
                // Allocate on stack
                let mut shared_map: SharedMem = MaybeUninit::zeroed().assume_init();
                // When the struct is written, parent can check that this closure ran at all
                shared_map.init = true;

                for (idx, lib) in libs_cstr.iter().enumerate() {
                    // Update number of successfully injected libs
                    shared_map.successes = idx as u8;

                    let res =
                        libc::dlopen(lib.to_bytes_with_nul().as_ptr() as *const c_char, RTLD_NOW);
                    if res.is_null() {
                        let dlerror_ptr = libc::dlerror();
                        if !dlerror_ptr.is_null() {
                            let dlerror_str = CStr::from_ptr(dlerror_ptr).to_bytes_with_nul();
                            // use error string capacity -1 to enforce nul terminator
                            let copy_len =
                                min(shared_map.error_string.len() - 1, dlerror_str.len());
                            shared_map.error_string[..copy_len]
                                .copy_from_slice(&dlerror_str[..copy_len]);
                        } else {
                            // It shouldn't be possible for dlerror to fail if dlopen failed,
                            // but might as well check
                            let dlerror_failure = b"dlerror() failed too\0";
                            shared_map.error_string[..dlerror_failure.len()]
                                .copy_from_slice(dlerror_failure);
                        }
                        (shared_map_ptr_for_target as *mut SharedMem).write(shared_map);
                        fence(Ordering::Release);
                        // The error code (but not string) is returned to the caller
                        // as if the target child had exited with it
                        // Should find some obscure code and use it
                        return Err(std::io::Error::from(ErrorKind::Unsupported));
                    }
                    // Store the handle
                    shared_map.handles[idx] = res;
                }
                // Safe from overflow, because max idx is u8::MAX - 1
                // If successes < libs len, error occurred in injection
                shared_map.successes += 1;
                // Store data
                (shared_map_ptr_for_target as *mut SharedMem).write(shared_map);
                fence(Ordering::Release);
                Ok(())
            })
        };
        return match cmd.spawn_get_task_port() {
            Ok((child, task_port)) => {
                if log::max_level() == log::LevelFilter::Trace {
                    log::trace!(
                        "Spawned pre-load child with pid {} and task port name {}",
                        child.id(),
                        task_port
                    );
                } else {
                    log::info!("Spawned pre-load child with pid {}", child.id());
                }

                // Spawn waits for `exec`, so the `pre_exec` closure has ran already
                // Errors should be caught in above
                // Struct guaranteed to be init now
                let shared_map = unsafe {
                    fence(Ordering::Acquire);
                    shared_map_ptr.read()
                };

                // Result has been read
                unsafe {
                    libc::munmap(
                        shared_map_ptr as *mut c_void,
                        SharedMem::page_rounded_size(),
                    )
                };

                // This is kinda useless, check file before launching?
                ensure_matching_arch(child.id() as pid_t)?;

                // Closure has ran without error, should be init
                assert!(shared_map.init);

                Ok(ProcHandle {
                    pid: child.id() as pid_t,
                    task_port,
                    child_handle: Some(child),
                    modules: libs.iter().cloned().zip(shared_map.handles).collect(),
                })
            }
            Err(e) => {
                fence(Ordering::Acquire);
                let shared_map = unsafe { shared_map_ptr.read() };
                // We did our read and are returning soon
                unsafe {
                    libc::munmap(
                        shared_map_ptr as *mut c_void,
                        SharedMem::page_rounded_size(),
                    );
                };
                if shared_map.init && libs.len() > shared_map.successes as usize {
                    // Loader code ran but did not succeed
                    let mut error_msg = format!(
                        "dlopen failed at library {} ({})",
                        shared_map.successes,
                        libs[shared_map.successes as usize].to_string_lossy()
                    );
                    if shared_map.error_string[0] != 0 {
                        error_msg += &format!(
                            ": {}",
                            CStr::from_bytes_until_nul(&shared_map.error_string)
                                .map(|c| c.to_string_lossy())
                                .unwrap_or("dlerror message unparseable too".into())
                        );
                    }
                    Err(Box::new(std::io::Error::new(ErrorKind::Other, error_msg)))
                } else {
                    // Either loader did not run or ran successfully; error unrelated
                    Err(Box::new(e))
                }
            }
        };
    }

    /// Inject the libraries at the given paths sequentially into the running process
    pub fn inject(&mut self, libs: &[PathBuf]) -> Result<(), InjectorError> {
        if libs.len() >= u8::MAX as usize {
            return Err(InjectorError::new(
                InjectorErrorKind::TooManyModules,
                format!(
                    "too many libraries for a single inject call (max {})",
                    u8::MAX - 1
                ),
            ));
        }

        // Create the buffer holding the path strings and the pointers to each string
        let (paths_buf, paths_buf_offsets): (Vec<u8>, Vec<usize>) = {
            let mut buf = vec![];
            let mut offsets: Vec<usize> = vec![];
            for path in libs.iter() {
                offsets.push(buf.len());
                buf.extend_from_slice(
                    CString::new(
                        path.clone()
                            .canonicalize()
                            .map_err(|e| {
                                std::io::Error::new(
                                    e.kind(),
                                    format!("{}: {}", path.to_string_lossy(), e),
                                )
                            })?
                            .into_os_string()
                            .as_bytes(),
                    )
                    .unwrap()
                    .as_bytes_with_nul(),
                );
            }
            (buf, offsets)
        };

        log::trace!(
            "Created string buffer for {} library paths ({} bytes)",
            paths_buf_offsets.len(),
            paths_buf.len()
        );

        // Extract shellcode from self
        let (code_seg_ptr, code_seg_size): (*mut u8, c_ulong) = {
            let mut seg_size = 0;
            let seg_ptr = unsafe {
                getsectiondata(
                    addr_of!(_mh_execute_header),
                    CStr::from_bytes_with_nul(b"__SHELLCODE\0")
                        .unwrap()
                        .as_ptr(),
                    CStr::from_bytes_with_nul(b"__inj_bootstrap\0")
                        .unwrap()
                        .as_ptr(),
                    &mut seg_size,
                )
            };
            assert!(
                !seg_ptr.is_null(),
                "could not locate injection bootstrap segment"
            );
            assert_ne!(
                seg_size, 0,
                "injection bootstrap segment is empty or missing"
            );
            (seg_ptr, seg_size)
        };

        log::trace!(
            "Found shellcode segment at 0x{:x} ({} bytes) by getsectiondata",
            code_seg_ptr as usize,
            code_seg_size
        );

        // Offset into the allocated code section where the instruction pointer will be placed
        let seg_ip_offset =
            unsafe { (bootstrap::bootstrap_entry as *const c_void).byte_offset_from(code_seg_ptr) };
        // Offset into the allocated code section from which pthread_entrypoint will be calculated
        let seg_pthread_routine_offset =
            unsafe { (bootstrap::inj_loop as *const c_void).byte_offset_from(code_seg_ptr) };
        assert!(
            seg_ip_offset < code_seg_size as isize,
            "bootstrap initial instruction pointer offset is larger than segment"
        );
        assert!(
            seg_pthread_routine_offset < code_seg_size as isize,
            "bootstrap pthread routine pointer offset is larger than segment"
        );

        log::trace!(
            "Found shellcode entrypoint offset 0x{:x} and pthread entrypoint offset 0x{:x}",
            seg_ip_offset,
            seg_pthread_routine_offset
        );

        // Unwrap cause memory errors are def not our problem
        let local_data_layout = Layout::from_size_align(
            size_of::<bootstrap::RemoteThreadData>() + paths_buf.len(),
            unsafe { libc::sysconf(_SC_PAGESIZE) } as usize,
        )
        .unwrap();
        let local_data = Global.allocate_zeroed(local_data_layout).unwrap();

        // Map the shellcode
        let remote_code_ptr = unsafe {
            let mut r: mach_vm_address_t = 0;
            let mut prot = VM_PROT_READ | VM_PROT_EXECUTE;
            mach_try!(mach_vm_remap(
                self.task_port,
                &mut r,
                code_seg_size as mach_vm_size_t, // Rounded to page size in function
                0,                               // Already page-aligned
                VM_FLAGS_ANYWHERE,
                mach_task_self(),
                code_seg_ptr as mach_vm_address_t,
                false as boolean_t,
                &mut prot,
                &mut prot,
                VM_INHERIT_SHARE
            ))?;
            r
        };
        log::trace!(
            "Mapped shellcode segment into target at 0x{:x}",
            remote_code_ptr
        );
        let remote_data_ptr = unsafe {
            let mut r: mach_vm_address_t = 0;
            let mut prot = VM_PROT_READ | VM_PROT_WRITE;
            mach_try!(mach_vm_remap(
                self.task_port,
                &mut r,
                local_data.len() as mach_vm_size_t, // Rounded to page size in function
                0,                                  // Already page-aligned
                VM_FLAGS_ANYWHERE,
                mach_task_self(),
                local_data.as_ptr() as *mut c_void as mach_vm_address_t,
                false as boolean_t,
                &mut prot,
                &mut prot,
                VM_INHERIT_SHARE
            ))?;
            r
        };
        log::trace!("Mapped data segment into target at 0x{:x}", remote_data_ptr);

        // Calculate the final string pointers
        let lib_ptrs: [*const c_char; u8::MAX as usize] = unsafe {
            let mut r = paths_buf_offsets
                .iter()
                .map(|&str_offset| {
                    (remote_data_ptr as *mut c_void)
                        .byte_add(size_of::<bootstrap::RemoteThreadData>() + str_offset)
                        as *const c_char
                })
                .collect::<Vec<*const c_char>>();
            // 0-extend to full length
            r.extend_from_slice(&vec![null(); u8::MAX as usize - paths_buf_offsets.len()]);
            r.try_into().unwrap()
        };
        let pthread_entrypoint_fnptr: bootstrap::pthread_routine_t = unsafe {
            std::mem::transmute(
                (remote_code_ptr as *mut c_void).byte_offset(seg_pthread_routine_offset)
                    as *const c_void,
            )
        };

        // Allocate stack
        let remote_stack_size: usize = 8 * 1024 * 1024; // 8 MiB
        let remote_stack_ptr = unsafe {
            let mut r: mach_vm_address_t = 0;
            mach_try!(mach_vm_allocate(
                self.task_port,
                &mut r,
                remote_stack_size as mach_vm_size_t,
                VM_FLAGS_ANYWHERE
            ))?;
            r
        };
        log::trace!(
            "Allocated 0x{:x} byte remote stack at 0x{:x}",
            remote_stack_size,
            remote_stack_ptr
        );

        // Create arg struct
        unsafe {
            // SAFETY: transmute is required to cast *const pthread_attr_t to *const c_void in args of fn-ptr
            // Because it's opaque type that we're not using anyways (we pass null)
            let pthread_create_from_mach_thread_fnptr: unsafe extern "C" fn(
                *mut bootstrap::pthread_t,
                *const c_void,
                bootstrap::pthread_routine_t,
                *mut c_void,
            ) -> c_int =
                std::mem::transmute(libc::pthread_create_from_mach_thread as *const c_void);
            local_data
                .cast::<bootstrap::RemoteThreadData>()
                .as_uninit_mut()
                .write(bootstrap::RemoteThreadData {
                    bootstrap_status: AtomicU8::new(0),
                    loader_status: AtomicU8::new(0),
                    tsd_base: remote_stack_ptr as *mut c_void,
                    thread_set_tsd_base: mach_util::traps::_thread_set_tsd_base,
                    mach_thread_self: mach2::mach_init::mach_thread_self,
                    thread_terminate,
                    pthread_create_from_mach_thread: pthread_create_from_mach_thread_fnptr,
                    pthread_exit: libc::pthread_exit,
                    dlopen: libc::dlopen,
                    dlerror: libc::dlerror,
                    pthread_entrypoint: pthread_entrypoint_fnptr,
                    lib_ptrs,
                    dlerror_str: [0; 1024],
                });
            copy_nonoverlapping(
                paths_buf.as_ptr(),
                local_data
                    .cast::<u8>()
                    .as_ptr()
                    .add(size_of::<bootstrap::RemoteThreadData>()),
                paths_buf.len(),
            );
            fence(Ordering::Release);
        };
        log::trace!("Wrote data struct and c-strings");

        // Setup remote thread execution state
        #[cfg(target_arch = "x86_64")]
        let (bootstrap_thread_flavor, mut bootstrap_thread_state, bootstrap_thread_size) = {
            use mach2::structs::x86_thread_state64_t;
            use mach2::thread_status::x86_THREAD_STATE64;

            let thread_state: x86_thread_state64_t = x86_thread_state64_t {
                // Start in bootstrap_entry
                __rip: remote_code_ptr + seg_ip_offset as mach_vm_address_t,
                // Stack grows down, start upwards and align to 16
                __rsp: (remote_stack_ptr + remote_stack_size as mach_vm_address_t) & !16,
                __rbp: (remote_stack_ptr + remote_stack_size as mach_vm_address_t) & !16,
                // First (and only) arg passed in this register
                __rdi: remote_data_ptr,
                ..Default::default()
            };
            (
                x86_THREAD_STATE64,
                thread_state,
                x86_thread_state64_t::count(),
            )
        };
        #[cfg(target_arch = "x86")]
        let (bootstrap_thread_flavor, mut bootstrap_thread_state, bootstrap_thread_size) = {
            use mach2::thread_status::x86_THREAD_STATE32;
            use mach_stubs::structs::x86_thread_state32_t;

            let thread_state: x86_thread_state32_t = x86_thread_state32_t {
                // Start in bootstrap_entry
                __eip: (remote_code_ptr + seg_ip_offset as mach_vm_address_t) as u32,
                // Stack grows down, start upwards and align to 16
                __esp: ((remote_stack_ptr + remote_stack_size as mach_vm_address_t) & !16) as u32,
                __ebp: ((remote_stack_ptr + remote_stack_size as mach_vm_address_t) & !16) as u32,
                // First (and only) arg passed in this register
                __ecx: remote_data_ptr as u32,
                ..Default::default()
            };
            (
                x86_THREAD_STATE32,
                thread_state,
                x86_thread_state32_t::count(),
            )
        };
        // TODO test following + add arm64e (w/ pointer-auth) support
        #[cfg(target_arch = "aarch64")]
        let (bootstrap_thread_flavor, mut bootstrap_thread_state, bootstrap_thread_size) = {
            use mach_stubs::structs::arm_thread_state64_t;
            use mach_stubs::structs::__DARWIN_ARM_THREAD_STATE64_FLAGS_NO_PTRAUTH;
            use mach_stubs::thread_status::ARM_THREAD_STATE64;

            let mut thread_state: arm_thread_state64_t = arm_thread_state64_t {
                // Start in bootstrap_entry
                __pc: remote_code_ptr + seg_ip_offset as mach_vm_address_t,
                // Stack grows down, start upwards and align to 16
                __sp: (remote_stack_ptr + remote_stack_size as mach_vm_address_t) & !16,
                __flags: __DARWIN_ARM_THREAD_STATE64_FLAGS_NO_PTRAUTH,
                ..Default::default()
            };
            // First (and only) arg passed in this register
            thread_state.__x[0] = remote_data_ptr;
            (
                ARM_THREAD_STATE64,
                thread_state,
                arm_thread_state64_t::count(),
            )
        };
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
        compile_error!("missing bootstrap thread state for target arch");

        // Launch the remote thread
        let remote_thread = unsafe {
            let mut r: mach_port_t = 0;
            mach_try!(thread_create_running(
                self.task_port,
                bootstrap_thread_flavor,
                addr_of_mut!(bootstrap_thread_state) as thread_state_t,
                bootstrap_thread_size,
                &mut r
            ))?;
            r
        };

        log::trace!(
            "Spawned remote thread with thread port name {}",
            remote_thread,
        );

        let mut timeout = 0;
        let mut status = 0;
        while timeout <= 10
            && unsafe {
                status = local_data
                    .cast::<bootstrap::RemoteThreadData>()
                    .as_ref()
                    .bootstrap_status
                    .load(Ordering::Acquire);
                status
            } <= 1
        {
            sleep(Duration::from_millis(100));
            timeout += 1;
        }

        // By this point, either the thread gave a terminal status or the 1sec timeout expired
        // This is hopefully unnecessary (child should call thread_terminate on itself)
        unsafe { thread_terminate(remote_thread) };
        match status {
            0 => {
                return Err(InjectorError::new(
                    InjectorErrorKind::RemoteFailure,
                    "Bootstrap thread did not execute",
                ));
            }
            1 => {
                return Err(InjectorError::new(
                    InjectorErrorKind::RemoteFailure,
                    "Bootstrap thread failed or stuck before loader thread spawn",
                ));
            }
            2 => {
                return Err(InjectorError::new(
                    InjectorErrorKind::RemoteFailure,
                    "Bootstrap thread failed to spawn loader thread",
                ));
            }
            3 => {
                log::trace!("Bootstrap thread launched loader thread");
            }
            other => {
                return Err(InjectorError::new(
                    InjectorErrorKind::RemoteFailure,
                    format!("Bootstrap status set to unknown value {}", other),
                ));
            }
        }

        let mut timeout = 0;
        let mut status = 0;
        while timeout <= libs.len()
            && unsafe {
                status = local_data
                    .cast::<bootstrap::RemoteThreadData>()
                    .as_ref()
                    .loader_status
                    .load(Ordering::Acquire);
                status
            } <= 1
        {
            sleep(Duration::from_millis(100));
            timeout += 1;
        }

        // Ensure that non-atomic struct members have been fully written
        fence(Ordering::SeqCst);
        let ret = match status {
            0 => {
                return Err(InjectorError::new(
                    InjectorErrorKind::RemoteFailure,
                    "Loader thread did not execute",
                ));
            }
            1 => {
                return Err(InjectorError::new(
                    InjectorErrorKind::RemoteFailure,
                    "Loader thread failed or stuck before `dlopen` loop",
                ));
            }
            2 => {
                log::error!("Loader thread failed to load all libraries, retrieving error");
                // SAFETY: 2 is a completed status, so this thread is sole accessor of data struct
                let handles = unsafe {
                    local_data
                        .cast::<bootstrap::RemoteThreadData>()
                        .as_ref()
                        .lib_ptrs
                };
                // status 2 is dlopen null retval, so look in handles for null
                let fail_idx = handles
                    .iter()
                    .enumerate()
                    .find_map(|(i, h)| if h.is_null() { Some(i) } else { None })
                    .unwrap();
                let mut err_str = format!("dlopen failed for library {}", fail_idx);

                // Load dlerror if it exists
                let dlerror_str = unsafe {
                    local_data
                        .cast::<bootstrap::RemoteThreadData>()
                        .as_ref()
                        .dlerror_str
                };
                if dlerror_str[0] != 0 {
                    // It feels stupid calling .to_string().as_str() but whatever
                    err_str += CStr::from_bytes_until_nul(&dlerror_str)
                        .map(|cstr| format!(": {}", cstr.to_string_lossy()))
                        .unwrap_or(format!(
                            ": {} (dlerror string unparseable)",
                            libs[fail_idx].to_string_lossy()
                        ))
                        .as_str();
                }

                Err(InjectorError::new(
                    InjectorErrorKind::PartialSuccess(fail_idx),
                    err_str,
                ))
            }
            3 => {
                log::trace!("Loader thread succeeded");
                Ok(())
            }
            other => {
                return Err(InjectorError::new(
                    InjectorErrorKind::RemoteFailure,
                    format!("Bootstrap status set to unknown value {}", other),
                ));
            }
        };

        // Loader process has exited and memory barrier passed, safe to read struct
        let handles = unsafe {
            local_data
                .cast::<bootstrap::RemoteThreadData>()
                .as_ref()
                .lib_ptrs
        }
        .into_iter()
        .map(|h| h as *mut c_void)
        .take_while(|h| !h.is_null());

        let mut new_modules: Vec<ModHandle> =
            std::iter::zip(libs.iter().cloned(), handles).collect();

        if log::max_level() == log::LevelFilter::Trace {
            log::trace!(
                "Got back {} module handles: {:?}",
                new_modules.len(),
                &new_modules
            );
        } else {
            log::info!(
                "Successfully injected {} modules of {}",
                new_modules.len(),
                libs.len()
            );
        }

        self.modules.append(&mut new_modules);

        // Deallocation time
        unsafe {
            mach_try!(mach_vm_deallocate(
                self.task_port,
                remote_code_ptr,
                code_seg_size as mach_vm_size_t
            ))?;
            mach_try!(mach_vm_deallocate(
                self.task_port,
                remote_data_ptr,
                local_data.len() as mach_vm_size_t
            ))?;
            mach_try!(mach_vm_deallocate(
                self.task_port,
                remote_stack_ptr,
                remote_stack_size as mach_vm_size_t
            ))?;
            Global.deallocate(local_data.cast::<u8>(), local_data_layout);
        }
        log::trace!("All remote allocations deallocated");

        ret
    }

    /// Ejects the given [ModHandle]s if they are owned by this instance
    #[doc(hidden)]
    pub fn eject(&mut self, handles: &[ModHandle]) -> Result<(), InjectorError> {
        // Get vec of ModHandles whose raw handles aren't owned by this struct
        let mut owned_mods = self.modules.clone();
        let mut non_owned: Vec<&ModHandle> = Vec::new();
        let mut non_owned_idx: Vec<usize> = Vec::new();
        // This is necessary to remove one match at a time rather than all matches
        for (idx, target) in handles.iter().enumerate() {
            if let Some(p) = owned_mods.iter().position(|c| c.1 == target.1) {
                owned_mods.remove(p);
            } else {
                non_owned_idx.push(idx);
                non_owned.push(target);
            }
        }

        if !non_owned.is_empty() {
            return Err(InjectorError::new(
                InjectorErrorKind::ModuleHandlesNotOwned(non_owned_idx),
                format!("non-owned ModHandle cannot be ejected: {:?}", non_owned),
            ));
        };

        let raw_handles = handles.iter().map(|m| m.1).collect::<Vec<*mut c_void>>();
        match unsafe { self.eject_raw(&raw_handles) } {
            Ok(()) => {
                self.modules = owned_mods;
                Ok(())
            }
            Err(e) => {
                if let InjectorErrorKind::PartialSuccess(idx) = e.kind() {
                    self.modules = self.modules.split_off(*idx);
                }
                Err(e)
            }
        }
    }

    /// Closes the given raw dlopen handles. This is not guaranteed to unload the associated modules
    /// as they are reference counted (dlclose must be called once for each dlopen call of a library)
    /// # SAFETY
    /// The caller must ensure that the handle is valid for the target process
    #[doc(hidden)]
    pub unsafe fn eject_raw(&mut self, _handles: &[*mut c_void]) -> Result<(), InjectorError> {
        Err(InjectorError::new(
            InjectorErrorKind::Unknown,
            "not yet impl",
        ))
    }

    /// Returns a reference counted copy of the underlying task port. The port refcount is incremented,
    /// so the consumer must call mach_port_deallocate
    pub fn get_task_port(&self) -> mach_port_t {
        self.task_port
    }

    /// Returns the process ID of the underlying process
    pub fn get_pid(&self) -> pid_t {
        self.pid
    }

    /// Returns the paths of the currently injected modules
    pub fn current_modules(&self) -> &[(PathBuf, *mut c_void)] {
        &self.modules
    }

    /// Returns the owned [Child] handle to the underlying process, if one exists. Effective only
    /// when initialized with [new](Self::new)
    // or [new_pre_inject](Self::new)
    pub fn take_proc_child(&mut self) -> Option<Child> {
        self.child_handle.take()
    }

    /// Kill target process forcefully (not yet impl)
    #[doc(hidden)]
    pub fn kill(self) {
        // TODO use mach APIs and task port instead
        unsafe { kill(self.pid, SIGKILL) };
        drop(self);
    }
}

impl Drop for ProcHandle {
    fn drop(&mut self) {
        unsafe { mach_port_deallocate(mach_task_self(), self.task_port) };
    }
}
