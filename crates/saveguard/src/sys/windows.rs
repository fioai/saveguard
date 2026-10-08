//! Windows. `ReplaceFileW` does what the Unix side does by hand: the new file takes over the old
//! one's attributes, ACLs, alternate data streams and creation time. What it can't keep is hard
//! links, so a file with several is overwritten in place.

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::ptr;
use std::thread;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_ACCESS_DENIED, ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION,
    ERROR_UNABLE_TO_MOVE_REPLACEMENT_2, ERROR_UNABLE_TO_REMOVE_REPLACED, GENERIC_READ,
    GENERIC_WRITE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetFileInformationByHandle, LockFileEx, MoveFileExW, ReplaceFileW,
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, LOCKFILE_EXCLUSIVE_LOCK,
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
};
use windows_sys::Win32::System::IO::{OVERLAPPED, OVERLAPPED_0, OVERLAPPED_0_0};

use super::{Facts, Failure, OverwriteError, Put, ReplaceError, Staged};
use crate::version::Stamp;

/// The file being saved over, as it was when the save started.
pub(crate) struct Original {
    meta: fs::Metadata,
    info: Option<Info>,
}

#[derive(Clone, Copy)]
struct Info {
    links: u32,
    volume: u32,
    index: u64,
    size: u64,
    write_time: u64,
}

impl Original {
    pub fn is_file(&self) -> bool {
        self.meta.file_type().is_file()
    }

    pub fn is_symlink(&self) -> bool {
        self.meta.file_type().is_symlink()
    }

    pub fn facts(&self) -> Facts {
        Facts {
            links: self.info.map_or(1, |info| u64::from(info.links)),
            mount_point: false,
            owner_kept: true,
            group_kept: true,
            setid: false,
            capabilities: false,
        }
    }

    /// Windows has no sticky, world-writable directories to distrust.
    pub fn trusted(&self, _path: &Path) -> bool {
        true
    }
}

pub(crate) fn trusted(_path: &Path, _meta: &fs::Metadata) -> bool {
    true
}

pub(crate) fn inspect(path: &Path) -> io::Result<Option<Original>> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let info = if meta.file_type().is_file() {
        open_attributes(path).and_then(|f| info(&f)).ok()
    } else {
        None
    };
    Ok(Some(Original { meta, info }))
}

/// Opens a file just to read its attributes, which needs no read access and gets in nobody's way.
fn open_attributes(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(path)
}

fn info(file: &File) -> io::Result<Info> {
    // SAFETY: the struct is plain data, filled in by the call.
    let mut i: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut i) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let join = |high: u32, low: u32| (u64::from(high) << 32) | u64::from(low);
    Ok(Info {
        links: i.nNumberOfLinks,
        volume: i.dwVolumeSerialNumber,
        index: join(i.nFileIndexHigh, i.nFileIndexLow),
        size: join(i.nFileSizeHigh, i.nFileSizeLow),
        write_time: join(
            i.ftLastWriteTime.dwHighDateTime,
            i.ftLastWriteTime.dwLowDateTime,
        ),
    })
}

fn wide(path: &Path) -> Vec<u16> {
    OsStr::new(path).encode_wide().chain(Some(0)).collect()
}

pub(crate) fn is_denied(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::PermissionDenied
}

/// The read-only attribute. A file closed to us by its ACL is found out when writing.
pub(crate) fn writable(path: &Path) -> io::Result<bool> {
    Ok(!fs::metadata(path)?.permissions().readonly())
}

pub(crate) fn dir_writable(_dir: &Path) -> bool {
    true
}

/// A new, empty file in `dir`. With `mode` `None` (contents that will replace an existing file)
/// only its owner can open it; `ReplaceFileW` gives it the original's ACL at the end. Otherwise it
/// gets the directory's inherited ACL, like any new file.
pub(crate) fn create_staged(
    dir: &Path,
    name: Option<&OsStr>,
    mode: Option<u32>,
) -> io::Result<Staged> {
    let mut collisions = 0;
    loop {
        let path = dir.join(super::temp_name(name));
        let created = match mode {
            Some(_) => OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path),
            None => create_private(&path),
        };
        match created {
            Ok(file) => return Ok(Staged { file, path }),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && collisions < 100 => {
                collisions += 1
            }
            Err(e) => return Err(e),
        }
    }
}

/// Creates a file with a DACL that gives its owner everything and inherits nothing from the
/// directory: "D:P(A;;FA;;;OW)", protected, one entry, all access for OWNER RIGHTS.
fn create_private(path: &Path) -> io::Result<File> {
    let sddl: Vec<u16> = "D:P(A;;FA;;;OW)".encode_utf16().chain(Some(0)).collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    if converted == 0 {
        return Err(io::Error::last_os_error());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let handle = unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    let error = io::Error::last_os_error();
    unsafe { LocalFree(descriptor) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(error);
    }
    // SAFETY: a handle CreateFileW just opened, owned by nothing else.
    Ok(unsafe { File::from_raw_handle(handle) })
}

pub(crate) fn prepare(_staged: &File, _original: &Original, _failures: &mut Vec<Failure>) {}

/// Nothing to do: `ReplaceFileW` carries the metadata over, and fails rather than lose it.
pub(crate) fn copy_metadata(_staged: &File, _original: &Original, _failures: &mut Vec<Failure>) {}

/// Puts the staged file at the target. It has to be closed for that, so on failure there's no
/// handle to give back; it can be opened again, since nothing changed its permissions.
pub(crate) fn replace(
    file: File,
    staged: &Path,
    target: &Path,
    put: Put,
    sync: bool,
) -> Result<Stamp, ReplaceError> {
    let before = match stamp_of(&file) {
        Ok(stamp) => stamp,
        Err(e) => return Err(ReplaceError::new(e, Some(file))),
    };
    // ReplaceFileW opens the staged file without sharing, so it must be closed first.
    drop(file);
    match put {
        Put::New | Put::OverLink => {
            move_file(staged, target, true, sync).map_err(|e| ReplaceError::new(e, None))?
        }
        Put::NewExclusive => {
            move_file(staged, target, false, sync).map_err(|e| ReplaceError::new(e, None))?
        }
        Put::OverFile => replace_file(staged, target, sync)?,
    }
    Ok(stamp_at(target).ok().flatten().unwrap_or(before))
}

fn move_file(from: &Path, to: &Path, replace: bool, sync: bool) -> io::Result<()> {
    let mut flags = 0;
    if replace {
        flags |= MOVEFILE_REPLACE_EXISTING;
    }
    if sync {
        flags |= MOVEFILE_WRITE_THROUGH;
    }
    if unsafe { MoveFileExW(wide(from).as_ptr(), wide(to).as_ptr(), flags) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// `ReplaceFileW`, with the error cases its documentation describes. The old file is moved to a
/// backup name rather than deleted, because if the last step fails without one, the documentation
/// can't say where the old file went.
fn replace_file(staged: &Path, target: &Path, sync: bool) -> Result<(), ReplaceError> {
    let backup = target.with_file_name(super::temp_name(target.file_name()));
    let (t, s, b) = (wide(target), wide(staged), wide(&backup));
    let mut delay = Duration::from_millis(1);
    loop {
        let ok = unsafe {
            ReplaceFileW(
                t.as_ptr(),
                s.as_ptr(),
                b.as_ptr(),
                0,
                ptr::null(),
                ptr::null(),
            )
        };
        if ok != 0 {
            finish(target, &backup, sync);
            return Ok(());
        }
        let code = unsafe { GetLastError() };
        match code {
            // Virus scanners, indexers and sync clients open files briefly: wait for them,
            // for about half a second in all.
            ERROR_SHARING_VIOLATION
            | ERROR_LOCK_VIOLATION
            | ERROR_ACCESS_DENIED
            | ERROR_UNABLE_TO_REMOVE_REPLACED
                if delay < Duration::from_millis(500) =>
            {
                thread::sleep(delay);
                delay *= 2;
            }
            // The old file is now at `backup` and the new one is still staged. Move the new one
            // into place, or else the old one back; if neither works, say where both are.
            ERROR_UNABLE_TO_MOVE_REPLACEMENT_2 => {
                let error = match move_file(staged, target, false, true) {
                    Ok(()) => {
                        finish(target, &backup, sync);
                        return Ok(());
                    }
                    Err(e) => e,
                };
                return Err(match move_file(&backup, target, false, true) {
                    Ok(()) => ReplaceError::new(error, None),
                    Err(_) => ReplaceError {
                        error,
                        file: None,
                        stranded: Some(backup),
                    },
                });
            }
            // Including ERROR_UNABLE_TO_MOVE_REPLACEMENT: with a backup name, nothing moved.
            _ => {
                return Err(ReplaceError::new(
                    io::Error::from_raw_os_error(code as i32),
                    None,
                ))
            }
        }
    }
}

/// After a replace: flush the file (`ReplaceFileW` has no write-through option, so this is the
/// best that can be done), and delete the old file, waiting a little for anything holding it.
fn finish(target: &Path, backup: &Path, sync: bool) {
    if sync {
        if let Ok(file) = OpenOptions::new().write(true).open(target) {
            let _ = file.sync_all();
        }
    }
    let mut delay = Duration::from_millis(1);
    loop {
        match fs::remove_file(backup) {
            Ok(()) => return,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return,
            Err(_) if delay < Duration::from_millis(500) => {
                thread::sleep(delay);
                delay *= 2;
            }
            Err(_) => return,
        }
    }
}

/// Any failure to replace, except the file having vanished, is worth an overwrite in place:
/// a lock that outlasted the retries, a file system without `ReplaceFileW`, an ACL that couldn't
/// be carried over.
pub(crate) fn rename_refused(e: &io::Error) -> bool {
    e.kind() != io::ErrorKind::NotFound
}

/// Opens the file to be overwritten, if it's still the file inspected when the save began, and
/// locks it so that two saveguard saves overwriting it take turns. The lock is on one byte far
/// past the end: Windows locks are mandatory, and locking the contents would make other programs'
/// reads fail.
pub(crate) fn open_existing(target: &Path, original: &Original) -> io::Result<Option<File>> {
    let file = OpenOptions::new().write(true).open(target)?;
    if let Some(expected) = original.info {
        let now = info(&file)?;
        if now.volume != expected.volume || now.index != expected.index {
            return Ok(None);
        }
    }
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    overlapped.Anonymous = OVERLAPPED_0 {
        Anonymous: OVERLAPPED_0_0 {
            Offset: 0xFFFF_FFFE,
            OffsetHigh: 0x7FFF_FFFF,
        },
    };
    // Without LOCKFILE_FAIL_IMMEDIATELY this waits for the lock. A file system that can't lock
    // fails it, and then the save carries on without.
    unsafe {
        LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK,
            0,
            1,
            0,
            &mut overlapped,
        )
    };
    Ok(Some(file))
}

/// Copies the staged contents, from the start of `from`, into `to`, the file from
/// [`open_existing`].
pub(crate) fn overwrite(
    from: &mut File,
    to: &mut File,
    len: u64,
    sync: bool,
) -> Result<Stamp, OverwriteError> {
    let before = |error| OverwriteError {
        touched: false,
        error,
    };
    let after = |error| OverwriteError {
        touched: true,
        error,
    };
    from.seek(SeekFrom::Start(0)).map_err(before)?;
    to.seek(SeekFrom::Start(0)).map_err(before)?;
    io::copy(from, to).map_err(after)?;
    to.set_len(len).map_err(after)?;
    if sync {
        to.sync_all().map_err(after)?;
    }
    stamp_of(to).map_err(after)
}

pub(crate) fn stamp_of(file: &File) -> io::Result<Stamp> {
    let info = info(file)?;
    Ok(Stamp {
        dev: u64::from(info.volume),
        ino: info.index,
        size: info.size,
        mtime: info.write_time as i64,
    })
}

pub(crate) fn stamp_at(path: &Path) -> io::Result<Option<Stamp>> {
    match open_attributes(path) {
        Ok(file) => stamp_of(&file).map(Some),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
