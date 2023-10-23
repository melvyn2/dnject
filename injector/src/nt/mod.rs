// This is basically just a wrapper around dll-syringe

use dll_syringe::error::InjectError;
use std::path::PathBuf;
use std::process::{Child, Command};

use libc::c_void;

use dll_syringe::process::{OwnedProcess, Process};
use dll_syringe::Syringe;

use crate::{InjectorError, InjectorErrorKind, ModHandle};

pub struct ProcHandle {
    inner: Syringe,
    modules: Vec<ModHandle>,
}

impl ProcHandle {
    pub fn new(mut cmd: Command) -> Result<Self, InjectorError> {
        let child = cmd.spawn()?;
        let syringe = Syringe::for_process(OwnedProcess::from_child(child));
        Ok(Self {
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
                    dbg!(&e);
                    return Err(match e {
                        InjectError::IllegalPath(_) => {
                            // Uncommon enough not to care about
                            // Does PathBuf allow nuls?
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
                            "Target process exited.",
                        ),
                        InjectError::UnsupportedTarget => InjectorError::new(
                            InjectorErrorKind::InvalidArchitecture,
                            "Target architecture not supported by injector.",
                        ),
                        InjectError::ArchitectureMismatch => InjectorError::new(
                            InjectorErrorKind::InvalidArchitecture,
                            format!(
                                "Module architecture does not match target: {}",
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
    pub fn kill(self) -> Result<(), InjectorError> {
        self.inner.process().kill().map_err(|e| e.into())
    }

    pub fn child(&mut self) -> &mut Option<Child> {
        todo!()
    }
}

impl TryFrom<i32> for ProcHandle {
    type Error = InjectorError;

    fn try_from(pid: i32) -> Result<Self, Self::Error> {
        // TODO check if attach permissions error
        let syringe = Syringe::for_process(OwnedProcess::from_pid(pid as u32)?);
        Ok(Self {
            inner: syringe,
            modules: Vec::new(),
        })
    }
}
