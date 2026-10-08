//! The C API, declared in `include/saveguard.h`.
#![allow(non_camel_case_types)]

use std::cell::RefCell;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use sg::{Durability, Error, Lost, Method, Options, Reason, Strategy, Version};

#[repr(C)]
pub struct saveguard_version {
    opaque: [u64; 8],
}

#[repr(C)]
pub struct saveguard_options {
    strategy: u32,
    flags: u32,
    mode: u32,
    unchanged_since: *const saveguard_version,
}

#[repr(C)]
pub struct saveguard_report {
    method: u32,
    reasons: u32,
    lost: u32,
    version: saveguard_version,
}

const OK: c_int = 0;
const ERR_IO: c_int = -1;
const ERR_CONFLICT: c_int = -2;
const ERR_EXISTS: c_int = -3;
const ERR_NOT_A_FILE: c_int = -4;
const ERR_READ_ONLY: c_int = -5;
const ERR_SYMLINK_LOOP: c_int = -6;
const ERR_INTERRUPTED: c_int = -7;
const ERR_INVALID: c_int = -8;

const NO_FOLLOW: u32 = 0x1;
const NO_SYNC: u32 = 0x2;
const CREATE_NEW: u32 = 0x4;

thread_local! {
    static LAST: RefCell<(CString, c_int)> = RefCell::new((CString::default(), 0));
}

/// Records a failure for `saveguard_last_error` and returns its code.
fn fail(code: c_int, message: impl Into<String>, os_error: c_int) -> c_int {
    let message = CString::new(message.into().replace('\0', "")).unwrap_or_default();
    LAST.with(|last| *last.borrow_mut() = (message, os_error));
    code
}

fn fail_with(e: &Error) -> c_int {
    let code = match e {
        Error::Conflict { .. } => ERR_CONFLICT,
        Error::Exists { .. } => ERR_EXISTS,
        Error::NotAFile { .. } => ERR_NOT_A_FILE,
        Error::ReadOnly { .. } => ERR_READ_ONLY,
        Error::SymlinkLoop { .. } => ERR_SYMLINK_LOOP,
        Error::Interrupted { .. } => ERR_INTERRUPTED,
        _ => ERR_IO,
    };
    let os_error = match e {
        Error::Io { source, .. } | Error::Interrupted { source, .. } => {
            source.raw_os_error().unwrap_or(0)
        }
        _ => 0,
    };
    fail(code, e.to_string(), os_error)
}

/// Runs `f`, turning a panic into an error rather than unwinding into C.
fn guard(f: impl FnOnce() -> c_int) -> c_int {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| fail(ERR_IO, "saveguard panicked", 0))
}

unsafe fn path_from(path: *const c_char) -> Result<PathBuf, c_int> {
    if path.is_null() {
        return Err(fail(ERR_INVALID, "the path is NULL", 0));
    }
    let bytes = CStr::from_ptr(path).to_bytes();
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(PathBuf::from(std::ffi::OsStr::from_bytes(bytes)))
    }
    #[cfg(not(unix))]
    {
        std::str::from_utf8(bytes)
            .map(PathBuf::from)
            .map_err(|_| fail(ERR_INVALID, "the path isn't UTF-8", 0))
    }
}

unsafe fn options_from(options: *const saveguard_options) -> Result<Options, c_int> {
    let mut opts = Options::new();
    let Some(o) = options.as_ref() else {
        return Ok(opts);
    };
    opts.strategy(match o.strategy {
        0 => Strategy::Auto,
        1 => Strategy::Replace,
        2 => Strategy::Overwrite,
        n => return Err(fail(ERR_INVALID, format!("unknown strategy {n}"), 0)),
    });
    if o.flags & !(NO_FOLLOW | NO_SYNC | CREATE_NEW) != 0 {
        return Err(fail(
            ERR_INVALID,
            format!("unknown flags {:#x}", o.flags),
            0,
        ));
    }
    opts.follow_symlinks(o.flags & NO_FOLLOW == 0);
    if o.flags & NO_SYNC != 0 {
        opts.durability(Durability::None);
    }
    opts.create_new(o.flags & CREATE_NEW != 0);
    if o.mode != 0 {
        opts.mode(o.mode);
    }
    if let Some(v) = o.unchanged_since.as_ref() {
        let version = Version::from_raw(v.opaque).ok_or_else(|| {
            fail(
                ERR_INVALID,
                "unchanged_since isn't a version saveguard made",
                0,
            )
        })?;
        opts.unchanged_since(&version);
    }
    Ok(opts)
}

fn method_code(method: Method) -> u32 {
    match method {
        Method::Created => 1,
        Method::Replaced => 2,
        Method::Overwrote => 3,
    }
}

fn reason_bits(reasons: &[Reason]) -> u32 {
    reasons.iter().fold(0, |bits, reason| {
        bits | match reason {
            Reason::Requested => 0x01,
            Reason::HardLinks(_) => 0x02,
            Reason::MountPoint => 0x04,
            Reason::DirectoryNotWritable => 0x08,
            Reason::Owner => 0x10,
            Reason::Group => 0x20,
            Reason::RenameFailed(_) => 0x80,
            _ => 0x40,
        }
    })
}

fn lost_bits(lost: &[Lost]) -> u32 {
    lost.iter().fold(0, |bits, lost| {
        bits | match lost {
            Lost::HardLinks(_) => 0x001,
            Lost::Owner => 0x002,
            Lost::Group => 0x004,
            Lost::Permissions => 0x008,
            Lost::SetId => 0x010,
            Lost::Capabilities => 0x020,
            Lost::Acl => 0x040,
            Lost::SecurityLabel => 0x080,
            Lost::Flags => 0x200,
            _ => 0x100,
        }
    })
}

/// # Safety
/// As documented in `saveguard.h`: `path` is a NUL-terminated string, `data` points to `len`
/// readable bytes, and `options` and `report` are NULL or valid.
#[no_mangle]
pub unsafe extern "C" fn saveguard_save(
    path: *const c_char,
    data: *const c_void,
    len: usize,
    options: *const saveguard_options,
    report: *mut saveguard_report,
) -> c_int {
    guard(|| {
        let path = match path_from(path) {
            Ok(path) => path,
            Err(code) => return code,
        };
        if data.is_null() && len != 0 {
            return fail(ERR_INVALID, "data is NULL", 0);
        }
        let bytes: &[u8] = if len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(data.cast(), len)
        };
        let opts = match options_from(options) {
            Ok(opts) => opts,
            Err(code) => return code,
        };
        match opts.save(&path, bytes) {
            Ok(r) => {
                if let Some(out) = report.as_mut() {
                    *out = saveguard_report {
                        method: method_code(r.method),
                        reasons: reason_bits(&r.reasons),
                        lost: lost_bits(&r.lost),
                        version: saveguard_version {
                            opaque: r.version.to_raw(),
                        },
                    };
                }
                OK
            }
            Err(e) => fail_with(&e),
        }
    })
}

/// # Safety
/// `path` is a NUL-terminated string; `options` and `report` are NULL or valid.
#[no_mangle]
pub unsafe extern "C" fn saveguard_plan(
    path: *const c_char,
    options: *const saveguard_options,
    report: *mut saveguard_report,
) -> c_int {
    guard(|| {
        let path = match path_from(path) {
            Ok(path) => path,
            Err(code) => return code,
        };
        let opts = match options_from(options) {
            Ok(opts) => opts,
            Err(code) => return code,
        };
        match opts.plan(&path) {
            Ok(plan) => {
                if let Some(out) = report.as_mut() {
                    *out = saveguard_report {
                        method: method_code(plan.method),
                        reasons: reason_bits(&plan.reasons),
                        lost: lost_bits(&plan.lost),
                        version: saveguard_version { opaque: [0; 8] },
                    };
                }
                OK
            }
            Err(e) => fail_with(&e),
        }
    })
}

/// # Safety
/// `path` is a NUL-terminated string; `data` and `len` are valid; `version` is NULL or valid.
#[no_mangle]
pub unsafe extern "C" fn saveguard_read(
    path: *const c_char,
    data: *mut *mut u8,
    len: *mut usize,
    version: *mut saveguard_version,
) -> c_int {
    guard(|| {
        let path = match path_from(path) {
            Ok(path) => path,
            Err(code) => return code,
        };
        if data.is_null() || len.is_null() {
            return fail(ERR_INVALID, "data or len is NULL", 0);
        }
        match sg::read(&path) {
            Ok((bytes, v)) => {
                *len = bytes.len();
                *data = into_buffer(bytes);
                if let Some(out) = version.as_mut() {
                    out.opaque = v.to_raw();
                }
                OK
            }
            Err(e) => fail_with(&e),
        }
    })
}

/// Buffers handed to C carry their length in the 8 bytes before them, for `saveguard_free`.
fn into_buffer(bytes: Vec<u8>) -> *mut u8 {
    let mut buf = Vec::with_capacity(bytes.len() + 8);
    buf.extend_from_slice(&(bytes.len() as u64).to_ne_bytes());
    buf.extend_from_slice(&bytes);
    let base = Box::into_raw(buf.into_boxed_slice()) as *mut u8;
    unsafe { base.add(8) }
}

/// # Safety
/// `data` is NULL or a buffer from `saveguard_read` that hasn't been freed.
#[no_mangle]
pub unsafe extern "C" fn saveguard_free(data: *mut u8) {
    if data.is_null() {
        return;
    }
    let base = data.sub(8);
    let len = u64::from_ne_bytes(*(base as *const [u8; 8])) as usize;
    drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
        base,
        len + 8,
    )));
}

/// # Safety
/// `path` is a NUL-terminated string and `version` is valid.
#[no_mangle]
pub unsafe extern "C" fn saveguard_version_of(
    path: *const c_char,
    version: *mut saveguard_version,
) -> c_int {
    guard(|| {
        let path = match path_from(path) {
            Ok(path) => path,
            Err(code) => return code,
        };
        let Some(out) = version.as_mut() else {
            return fail(ERR_INVALID, "version is NULL", 0);
        };
        match Version::of(&path) {
            Ok(v) => {
                out.opaque = v.to_raw();
                OK
            }
            Err(e) => fail_with(&e),
        }
    })
}

#[no_mangle]
pub extern "C" fn saveguard_last_error() -> *const c_char {
    LAST.with(|last| last.borrow().0.as_ptr())
}

#[no_mangle]
pub extern "C" fn saveguard_last_os_error() -> c_int {
    LAST.with(|last| last.borrow().1)
}
