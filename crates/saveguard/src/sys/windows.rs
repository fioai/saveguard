//! Windows. `ReplaceFileW` does what the Unix side does by hand: the new file takes over the old
//! one's attributes, ACLs, alternate data streams and creation time. What it can't keep is hard
//! links, so a file with several is overwritten in place.

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::thread;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_ACCESS_DENIED, ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION,
    ERROR_UNABLE_TO_MOVE_REPLACEMENT_2, ERROR_UNABLE_TO_REMOVE_REPLACED,
};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, MoveFileExW, ReplaceFileW, BY_HANDLE_FILE_INFORMATION,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
};

use super::{Facts, Failure, OverwriteError, Put, Staged};
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

pub(crate) fn create_staged(dir: &Path, _mode: u32) -> io::Result<Staged> {
    let mut collisions = 0;
    loop {
        let path = dir.join(super::temp_name());
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => return Ok(Staged { file, path }),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && collisions < 100 => {
                collisions += 1
            }
            Err(e) => return Err(e),
        }
    }
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
) -> Result<Stamp, (io::Error, Option<File>)> {
    let before = match stamp_of(&file) {
        Ok(stamp) => stamp,
        Err(e) => return Err((e, Some(file))),
    };
    // ReplaceFileW opens the staged file without sharing, so it must be closed first.
    drop(file);
    let done = match put {
        Put::New | Put::OverLink => move_file(staged, target, true, sync),
        Put::NewExclusive => move_file(staged, target, false, sync),
        Put::OverFile => replace_file(staged, target),
    };
    match done {
        Ok(()) => Ok(stamp_at(target).ok().flatten().unwrap_or(before)),
        Err(e) => Err((e, None)),
    }
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
fn replace_file(staged: &Path, target: &Path) -> io::Result<()> {
    let backup = target.with_file_name(super::temp_name());
    let (t, s, b) = (wide(target), wide(staged), wide(&backup));
    let mut delay = Duration::from_millis(1);
    loop {
        let ok = unsafe {
            ReplaceFileW(
                t.as_ptr(),
                s.as_ptr(),
                b.as_ptr(),
                0,
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if ok != 0 {
            let _ = fs::remove_file(&backup);
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
            // The old file is now at `backup` and the new one is still staged.
            ERROR_UNABLE_TO_MOVE_REPLACEMENT_2 => {
                return match move_file(staged, target, false, true) {
                    Ok(()) => {
                        let _ = fs::remove_file(&backup);
                        Ok(())
                    }
                    Err(e) => {
                        let _ = move_file(&backup, target, false, true);
                        Err(e)
                    }
                };
            }
            // Including ERROR_UNABLE_TO_MOVE_REPLACEMENT: with a backup name, nothing moved.
            _ => return Err(io::Error::from_raw_os_error(code as i32)),
        }
    }
}

/// Any failure to replace, except the file having vanished, is worth an overwrite in place:
/// a lock that outlasted the retries, a file system without `ReplaceFileW`, an ACL that couldn't
/// be carried over.
pub(crate) fn rename_refused(e: &io::Error) -> bool {
    e.kind() != io::ErrorKind::NotFound
}

/// Copies the staged contents, from the start of `from`, into the existing file at `target`.
pub(crate) fn overwrite(
    from: &mut File,
    target: &Path,
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
    let mut to = OpenOptions::new()
        .write(true)
        .open(target)
        .map_err(before)?;
    io::copy(from, &mut to).map_err(after)?;
    to.set_len(len).map_err(after)?;
    if sync {
        to.sync_all().map_err(after)?;
    }
    stamp_of(&to).map_err(after)
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
