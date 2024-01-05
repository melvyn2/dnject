// This is basically just a wrapper around dll-syringe

use std::os::windows::io::{AsHandle, FromRawHandle, IntoRawHandle};
use std::path::PathBuf;
use std::process::{Child, Command};

use libc::c_void;

use dll_syringe::error::{EjectError, InjectError};
use dll_syringe::process::{BorrowedProcessModule, ModuleHandle, OwnedProcess, Process};
use dll_syringe::Syringe;

use crate::{InjectorError, InjectorErrorKind, ModHandle};

pub struct ProcHandle {
    child: Option<Child>,
    inner: Syringe,
    modules: Vec<ModHandle>,
}

impl ProcHandle {
    pub fn new(mut cmd: Command) -> Result<Self, InjectorError> {
        let child = cmd.spawn()?;
        let syringe_process = unsafe {
            let handle_2 = child.as_handle().try_clone_to_owned().unwrap();
            OwnedProcess::from_raw_handle(handle_2.into_raw_handle())
        };
        let syringe = Syringe::for_process(syringe_process);
        Ok(Self {
            child: Some(child),
            inner: syringe,
            modules: Vec::new(),
        })
    }

    pub fn inject(&mut self, libs: &[PathBuf]) -> Result<(), InjectorError> {
        for (idx, lib) in libs.iter().enumerate() {
            match self.inner.inject(lib) {
                Ok(module) => self
                    .modules
                    .push((lib.clone(), module.handle() as *mut c_void)),
                Err(e) => {
                    return Err(match e {
                        InjectError::IllegalPath(_) => {
                            // Uncommon enough not to care about
                            // TODO does PathBuf allow nuls?
                            InjectorError::new(
                                InjectorErrorKind::Unknown,
                                format!("'{}' contains illegal nul byte.", lib.to_string_lossy()),
                            )
                        }
                        InjectError::Io(ioerr) => InjectorError::new(
                            InjectorErrorKind::IoError(ioerr.kind()),
                            format!("{}: {}", lib.to_string_lossy(), ioerr),
                        ),
                        InjectError::RemoteIo(ioerr) => InjectorError::new(
                            InjectorErrorKind::LoaderError(idx),
                            format!("{}: {}", lib.to_string_lossy(), ioerr),
                        ),
                        InjectError::RemoteException(code) => InjectorError::new(
                            InjectorErrorKind::LoaderError(idx),
                            format!("during {}: {}", lib.to_string_lossy(), code),
                        ),
                        InjectError::ProcessInaccessible => InjectorError::new(
                            InjectorErrorKind::ProcessExited,
                            "target process exited",
                        ),
                        InjectError::UnsupportedTarget => InjectorError::new(
                            InjectorErrorKind::InvalidArchitecture,
                            "target architecture not supported by injector",
                        ),
                        InjectError::ArchitectureMismatch => InjectorError::new(
                            InjectorErrorKind::InvalidArchitecture,
                            format!(
                                "module architecture does not match target: {}",
                                lib.to_string_lossy()
                            ),
                        ),
                        InjectError::Goblin(goblinerr) => InjectorError::new(
                            InjectorErrorKind::LoaderError(idx),
                            format!("could not parse {}: {}", lib.to_string_lossy(), goblinerr),
                        ),
                    });
                }
            }
        }
        Ok(())
    }

    /// Ejects the given [ModHandle]s if they are owned by this instance,
    /// or all injected modules if `handles` is [None]
    pub fn eject(&mut self, handles: Option<&[ModHandle]>) -> Result<(), InjectorError> {
        todo!()
    }

    /// Closes the given raw module handles. This is not guaranteed to unload the associated modules
    /// as they are reference counted (FreeLibrary must be called once for each LoadLibrary call of a library)
    /// # Safety
    /// The caller must ensure that the handle is valid for the target process
    pub unsafe fn eject_raw(&mut self, handles: &[*mut c_void]) -> Result<(), InjectorError> {
        for (idx, &handle) in handles.iter().enumerate() {
            let syringe_handle =
                BorrowedProcessModule::new_unchecked(handle as ModuleHandle, self.inner.process());
            match self.inner.eject(syringe_handle) {
                Ok(_) => {}
                Err(e) => {
                    return Err(match e {
                        EjectError::Io(ioerr) => InjectorError::new(
                            InjectorErrorKind::IoError(ioerr.kind()),
                            format!("{:?}: {}", handle, ioerr),
                        ),
                        EjectError::ModuleInaccessible => InjectorError::new(
                            InjectorErrorKind::Unknown,
                            format!("{:?}: module does not exist", handle),
                        ),
                        EjectError::RemoteIo(ioerr) => InjectorError::new(
                            InjectorErrorKind::LoaderError(idx),
                            format!("{:?}: {}", handle, ioerr),
                        ),
                        EjectError::RemoteException(code) => InjectorError::new(
                            InjectorErrorKind::LoaderError(idx),
                            format!("during {:?}: {}", handle, code),
                        ),
                        EjectError::ProcessInaccessible => InjectorError::new(
                            InjectorErrorKind::ProcessExited,
                            "target process exited",
                        ),
                        EjectError::UnsupportedTarget => InjectorError::new(
                            InjectorErrorKind::InvalidArchitecture,
                            "target architecture not supported by injector",
                        ),
                        EjectError::Goblin(goblinerr) => InjectorError::new(
                            InjectorErrorKind::LoaderError(idx),
                            format!("could not parse module {:?}: {}", handle, goblinerr),
                        ),
                    });
                }
            }
        }
        Ok(())
    }

    pub fn kill(self) -> Result<(), InjectorError> {
        self.inner.process().kill().map_err(|e| e.into())
    }

    pub fn child(&mut self) -> &mut Option<Child> {
        &mut self.child
    }

    pub fn current_modules(&self) -> &[ModHandle] {
        &self.modules
    }
}

impl TryFrom<i32> for ProcHandle {
    type Error = InjectorError;

    fn try_from(pid: i32) -> Result<Self, Self::Error> {
        // TODO check if attach permissions error
        let syringe = Syringe::for_process(OwnedProcess::from_pid(pid as u32)?);
        Ok(Self {
            child: None,
            inner: syringe,
            modules: Vec::new(),
        })
    }
}
