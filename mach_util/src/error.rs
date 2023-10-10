use std::fmt::{Display, Formatter};

use mach2::kern_return;
use mach2::kern_return::kern_return_t;
use mach2::message;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(i32)]
pub enum MachErrorKind {
    KERN_SUCCESS = kern_return::KERN_SUCCESS,
    KERN_INVALID_ADDRESS = kern_return::KERN_INVALID_ADDRESS,
    KERN_PROTECTION_FAILURE = kern_return::KERN_PROTECTION_FAILURE,
    KERN_NO_SPACE = kern_return::KERN_NO_SPACE,
    KERN_INVALID_ARGUMENT = kern_return::KERN_INVALID_ARGUMENT,
    KERN_FAILURE = kern_return::KERN_FAILURE,
    KERN_RESOURCE_SHORTAGE = kern_return::KERN_RESOURCE_SHORTAGE,
    KERN_NOT_RECEIVER = kern_return::KERN_NOT_RECEIVER,
    KERN_NO_ACCESS = kern_return::KERN_NO_ACCESS,
    KERN_MEMORY_FAILURE = kern_return::KERN_MEMORY_FAILURE,
    KERN_MEMORY_ERROR = kern_return::KERN_MEMORY_ERROR,
    KERN_ALREADY_IN_SET = kern_return::KERN_ALREADY_IN_SET,
    KERN_NOT_IN_SET = kern_return::KERN_NOT_IN_SET,
    KERN_NAME_EXISTS = kern_return::KERN_NAME_EXISTS,
    KERN_ABORTED = kern_return::KERN_ABORTED,
    KERN_INVALID_NAME = kern_return::KERN_INVALID_NAME,
    KERN_INVALID_TASK = kern_return::KERN_INVALID_TASK,
    KERN_INVALID_RIGHT = kern_return::KERN_INVALID_RIGHT,
    KERN_INVALID_VALUE = kern_return::KERN_INVALID_VALUE,
    KERN_UREFS_OVERFLOW = kern_return::KERN_UREFS_OVERFLOW,
    KERN_INVALID_CAPABILITY = kern_return::KERN_INVALID_CAPABILITY,
    KERN_RIGHT_EXISTS = kern_return::KERN_RIGHT_EXISTS,
    KERN_INVALID_HOST = kern_return::KERN_INVALID_HOST,
    KERN_MEMORY_PRESENT = kern_return::KERN_MEMORY_PRESENT,
    KERN_MEMORY_DATA_MOVED = kern_return::KERN_MEMORY_DATA_MOVED,
    KERN_MEMORY_RESTART_COPY = kern_return::KERN_MEMORY_RESTART_COPY,
    KERN_INVALID_PROCESSOR_SET = kern_return::KERN_INVALID_PROCESSOR_SET,
    KERN_POLICY_LIMIT = kern_return::KERN_POLICY_LIMIT,
    KERN_INVALID_POLICY = kern_return::KERN_INVALID_POLICY,
    KERN_INVALID_OBJECT = kern_return::KERN_INVALID_OBJECT,
    KERN_ALREADY_WAITING = kern_return::KERN_ALREADY_WAITING,
    KERN_DEFAULT_SET = kern_return::KERN_DEFAULT_SET,
    KERN_EXCEPTION_PROTECTED = kern_return::KERN_EXCEPTION_PROTECTED,
    KERN_INVALID_LEDGER = kern_return::KERN_INVALID_LEDGER,
    KERN_INVALID_MEMORY_CONTROL = kern_return::KERN_INVALID_MEMORY_CONTROL,
    KERN_INVALID_SECURITY = kern_return::KERN_INVALID_SECURITY,
    KERN_NOT_DEPRESSED = kern_return::KERN_NOT_DEPRESSED,
    KERN_TERMINATED = kern_return::KERN_TERMINATED,
    KERN_LOCK_SET_DESTROYED = kern_return::KERN_LOCK_SET_DESTROYED,
    KERN_LOCK_UNSTABLE = kern_return::KERN_LOCK_UNSTABLE,
    KERN_LOCK_OWNED = kern_return::KERN_LOCK_OWNED,
    KERN_LOCK_OWNED_SELF = kern_return::KERN_LOCK_OWNED_SELF,
    KERN_SEMAPHORE_DESTROYED = kern_return::KERN_SEMAPHORE_DESTROYED,
    KERN_RPC_SERVER_TERMINATED = kern_return::KERN_RPC_SERVER_TERMINATED,
    KERN_RPC_TERMINATE_ORPHAN = kern_return::KERN_RPC_TERMINATE_ORPHAN,
    KERN_RPC_CONTINUE_ORPHAN = kern_return::KERN_RPC_CONTINUE_ORPHAN,
    KERN_NOT_SUPPORTED = kern_return::KERN_NOT_SUPPORTED,
    KERN_NODE_DOWN = kern_return::KERN_NODE_DOWN,
    KERN_NOT_WAITING = kern_return::KERN_NOT_WAITING,
    KERN_OPERATION_TIMED_OUT = kern_return::KERN_OPERATION_TIMED_OUT,
    KERN_CODESIGN_ERROR = kern_return::KERN_CODESIGN_ERROR,
    KERN_POLICY_STATIC = kern_return::KERN_POLICY_STATIC,
    KERN_RETURN_MAX = kern_return::KERN_RETURN_MAX,

    MACH_SEND_IN_PROGRESS = message::MACH_SEND_IN_PROGRESS,
    MACH_SEND_INVALID_DATA = message::MACH_SEND_INVALID_DATA,
    MACH_SEND_INVALID_DEST = message::MACH_SEND_INVALID_DEST,
    MACH_SEND_TIMED_OUT = message::MACH_SEND_TIMED_OUT,
    MACH_SEND_INVALID_VOUCHER = message::MACH_SEND_INVALID_VOUCHER,
    MACH_SEND_INTERRUPTED = message::MACH_SEND_INTERRUPTED,
    MACH_SEND_MSG_TOO_SMALL = message::MACH_SEND_MSG_TOO_SMALL,
    MACH_SEND_INVALID_REPLY = message::MACH_SEND_INVALID_REPLY,
    MACH_SEND_INVALID_RIGHT = message::MACH_SEND_INVALID_RIGHT,
    MACH_SEND_INVALID_NOTIFY = message::MACH_SEND_INVALID_NOTIFY,
    MACH_SEND_INVALID_MEMORY = message::MACH_SEND_INVALID_MEMORY,
    MACH_SEND_NO_BUFFER = message::MACH_SEND_NO_BUFFER,
    MACH_SEND_TOO_LARGE = message::MACH_SEND_TOO_LARGE,
    MACH_SEND_INVALID_TYPE = message::MACH_SEND_INVALID_TYPE,
    MACH_SEND_INVALID_HEADER = message::MACH_SEND_INVALID_HEADER,
    MACH_SEND_INVALID_TRAILER = message::MACH_SEND_INVALID_TRAILER,
    MACH_SEND_INVALID_RT_OOL_SIZE = message::MACH_SEND_INVALID_RT_OOL_SIZE,

    MACH_RCV_IN_PROGRESS = message::MACH_RCV_IN_PROGRESS,
    MACH_RCV_INVALID_NAME = message::MACH_RCV_INVALID_NAME,
    MACH_RCV_TIMED_OUT = message::MACH_RCV_TIMED_OUT,
    MACH_RCV_TOO_LARGE = message::MACH_RCV_TOO_LARGE,
    MACH_RCV_INTERRUPTED = message::MACH_RCV_INTERRUPTED,
    MACH_RCV_PORT_CHANGED = message::MACH_RCV_PORT_CHANGED,
    MACH_RCV_INVALID_NOTIFY = message::MACH_RCV_INVALID_NOTIFY,
    MACH_RCV_INVALID_DATA = message::MACH_RCV_INVALID_DATA,
    MACH_RCV_PORT_DIED = message::MACH_RCV_PORT_DIED,
    MACH_RCV_IN_SET = message::MACH_RCV_IN_SET,
    MACH_RCV_HEADER_ERROR = message::MACH_RCV_HEADER_ERROR,
    MACH_RCV_BODY_ERROR = message::MACH_RCV_BODY_ERROR,
    MACH_RCV_INVALID_TYPE = message::MACH_RCV_INVALID_TYPE,
    MACH_RCV_SCATTER_SMALL = message::MACH_RCV_SCATTER_SMALL,
    MACH_RCV_INVALID_TRAILER = message::MACH_RCV_INVALID_TRAILER,
    MACH_RCV_IN_PROGRESS_TIMED = message::MACH_RCV_IN_PROGRESS_TIMED,
}

#[cfg(feature = "bincode")]
impl bincode::Encode for MachErrorKind {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        let val = (*self).into();
        <i32 as bincode::Encode>::encode(&val, encoder)?;
        Ok(())
    }
}

#[cfg(feature = "bincode")]
impl bincode::Decode for MachErrorKind {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        <i32 as bincode::Decode>::decode(decoder).map(Self::from)
    }
}

#[cfg(feature = "bincode")]
impl<'de> bincode::BorrowDecode<'de> for MachErrorKind {
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        <i32 as bincode::Decode>::decode(decoder).map(Self::from)
    }
}

impl From<kern_return_t> for MachErrorKind {
    fn from(value: kern_return_t) -> Self {
        // TODO massive troll here
        unsafe { std::mem::transmute(value) }
    }
}

// Explicitly don't want to have From conversion
#[allow(clippy::from_over_into)]
impl Into<kern_return_t> for MachErrorKind {
    fn into(self) -> kern_return_t {
        // SAFETY: inner representation is guaranteed to be i32 and variants are all valid error constants
        unsafe { std::mem::transmute(self) }
    }
}

impl Display for MachErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "bincode", derive(bincode::Encode, bincode::Decode))]
pub struct MachError {
    kind: MachErrorKind,
    msg: String,
}

impl MachError {
    pub fn new(kind: MachErrorKind, msg: String) -> Self {
        Self { kind, msg }
    }

    pub fn kind(&self) -> MachErrorKind {
        self.kind
    }
}

impl From<MachError> for std::io::Error {
    fn from(value: MachError) -> Self {
        Self::new(std::io::ErrorKind::Other, value.to_string())
    }
}

impl Display for MachError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl std::error::Error for MachError {}

/// Wrap a mach API that returns `kern_return_t` to return according `Result`s
#[macro_export]
macro_rules! mach_try {
    ($e:expr) => {{
        let kr = $e;
        if kr == $crate::error::MachErrorKind::KERN_SUCCESS as i32 {
            Ok(())
        } else {
            let err_str = ::std::format!(
                "`{}` failed with return code 0x{:x}: {}",
                ::std::stringify!($e).split_once('(').unwrap().0,
                kr,
                ::std::ffi::CStr::from_ptr($crate::mach_error::mach_error_string(kr))
                    .to_string_lossy()
            );
            // #[cfg(panic = "unwind")]
            // let err_str = format!("[{}:{}] {}", file!(), line!(), err_str);
            ::std::result::Result::Err($crate::error::MachError::new(kr.into(), err_str))
        }
    }};
}
