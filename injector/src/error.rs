// TODO probably switch to thiserror

#[derive(Debug, Clone)]
pub enum InjectorErrorKind {
    /// The injector crate or injected module do not support the architecture of the target process.
    InvalidArchitecture,
    /// An unspecified non-permissions-related error occurred while attaching to the target process.
    AttachFailure,
    /// Permissions to attach to the target process were denied.
    AttachPermission,
    /// The provided process handle is invalid.
    InvalidProcessHandle,
    /// The target process or handle no longer exists.
    ProcessExited,
    /// Modules passed to `eject` were not owned by the injector instance. The indexes in the argument array
    /// of the non-owned handles are returned.
    ModuleHandlesNotOwned(Vec<usize>),
    /// Too many arguments were passed to an injection/ejection function. See implementation-specific
    /// documentation in [ProcHandle](crate::ProcHandle).
    TooManyModules,
    /// Shellcode in the remote process failed to execute or complete the task.
    RemoteFailure,
    /// The OS module loader returned an error for the library or module whose index in the argument
    /// array is returned. The loader error message is contained in the error text.
    LoaderError(usize),
    /// Internal error to preserve currently-injected modules.
    #[doc(hidden)]
    PartialSuccessRaw(Vec<*mut libc::c_void>),
    /// A generic operating-system error occurred. The wrapped error is returned.
    IoError(std::io::ErrorKind),
    // TODO remove os-specific public error
    #[cfg(target_os = "macos")]
    /// A mach API failure occurred. The wrapped error is returned.
    MachError(mach_util::error::MachErrorKind),
    /// An unspecified error occurred.
    Unknown,
}

/// An error type returned by injector functions. See [InjectorErrorKind] for details of error kinds.
/// Often the error message (from `Debug` or `Display` formatting) will contain more details.
pub struct InjectorError {
    kind: InjectorErrorKind,
    msg: String,
}

impl std::fmt::Debug for InjectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.msg)
    }
}

impl std::fmt::Display for InjectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl std::error::Error for InjectorError {}

// This should be private but I'm using it in dnject when I shouldn't be...
#[doc(hidden)]
impl From<std::io::Error> for InjectorError {
    fn from(value: std::io::Error) -> Self {
        Self {
            kind: InjectorErrorKind::IoError(value.kind()),
            msg: value.to_string(),
        }
    }
}

impl InjectorError {
    pub(crate) fn new<S: ToString>(kind: InjectorErrorKind, msg: S) -> Self {
        Self {
            kind,
            msg: msg.to_string(),
        }
    }

    pub fn kind(&self) -> &InjectorErrorKind {
        &self.kind
    }
}
