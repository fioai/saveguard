//! Windows. The same plan as on Unix: give the staged file everything the original had, then
//! rename it over the original in one step. `ReplaceFileW` would carry the metadata over by
//! itself, but it isn't atomic: it moves the original aside before moving the new file in, and in
//! between there is no file at the path at all (CI caught readers getting "not found").
//!
//! What's matched: the owner (a mismatch means overwriting in place), the ACL (copied when it's
//! the file's own, and otherwise inherited from the same directory), the hidden, system and
//! not-indexed attributes, the creation time, and alternate data streams such as
//! `Zone.Identifier`. Hard links can't be kept, so a file with several is overwritten in place.

use std::ffi::{c_void, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};
use std::ptr;
use std::thread;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    LocalFree, ERROR_ACCESS_DENIED, ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION, GENERIC_READ,
    GENERIC_WRITE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    EqualSid, GetSecurityDescriptorControl, GetSecurityDescriptorDacl, ACL,
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SE_DACL_PROTECTED,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FileBasicInfo, FindClose, FindFirstStreamW, FindNextStreamW,
    FindStreamInfoStandard, GetFileInformationByHandle, LockFileEx, MoveFileExW,
    SetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, CREATE_NEW, FILE_ATTRIBUTE_COMPRESSED,
    FILE_ATTRIBUTE_ENCRYPTED, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FILE_ATTRIBUTE_SYSTEM, FILE_BASIC_INFO,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    LOCKFILE_EXCLUSIVE_LOCK, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, READ_CONTROL,
    WIN32_FIND_STREAM_DATA, WRITE_DAC,
};
use windows_sys::Win32::System::IO::{OVERLAPPED, OVERLAPPED_0, OVERLAPPED_0_0};

use super::{Facts, Failure, OverwriteError, Put, ReplaceError, Stage, Staged};
use crate::version::Stamp;
use crate::Lost;

/// The attributes a replacement takes over.
const KEPT_ATTRIBUTES: u32 =
    FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
/// Attributes a new file can't simply be given; a mismatch means overwriting in place.
const STORAGE_ATTRIBUTES: u32 = FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_ENCRYPTED;

/// The file being saved over, as it was when the save started.
pub(crate) struct Original {
    meta: fs::Metadata,
    path: PathBuf,
    info: Option<Info>,
    /// Open to read its owner and ACL from; `None` if that isn't allowed.
    file: Option<File>,
}

#[derive(Clone, Copy)]
struct Info {
    attributes: u32,
    creation: u64,
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
            // Found out in `prepare`, by comparing with the staged file's owner.
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
    let (info, file) = if meta.file_type().is_file() {
        let file = open_with(path, FILE_READ_ATTRIBUTES | READ_CONTROL).ok();
        let info = match &file {
            Some(file) => info(file).ok(),
            None => open_attributes(path).and_then(|f| info(&f)).ok(),
        };
        (info, file)
    } else {
        (None, None)
    };
    Ok(Some(Original {
        meta,
        path: path.to_path_buf(),
        info,
        file,
    }))
}

/// Opens a file just to read its attributes, which needs no read access and gets in nobody's way.
fn open_attributes(path: &Path) -> io::Result<File> {
    open_with(path, FILE_READ_ATTRIBUTES)
}

fn open_with(path: &Path, access: u32) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(access)
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
        attributes: i.dwFileAttributes,
        creation: join(
            i.ftCreationTime.dwHighDateTime,
            i.ftCreationTime.dwLowDateTime,
        ),
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

/// A new, empty file in `dir`. A [`Stage::Copy`] is private to its owner from the start; the
/// others get the directory's inherited ACL, as any new file does, and a [`Stage::Replacement`]
/// is then matched to the original by `prepare` before anything is written to it.
pub(crate) fn create_staged(dir: &Path, name: Option<&OsStr>, stage: Stage) -> io::Result<Staged> {
    let mut collisions = 0;
    loop {
        let path = dir.join(super::temp_name(name));
        let created = match stage {
            Stage::Copy => create_private(&path),
            // WRITE_DAC, to give it the original's ACL.
            Stage::New(_) | Stage::Replacement => OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .access_mode(GENERIC_READ | GENERIC_WRITE | WRITE_DAC)
                .open(&path),
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

/// The SDDL for a file only its owner can open: a protected DACL (nothing inherited from the
/// directory) with one entry, all access for OWNER RIGHTS.
const PRIVATE: &str = "D:P(A;;FA;;;OW)";

/// A security descriptor made from SDDL, freed on drop.
struct Descriptor(PSECURITY_DESCRIPTOR);

impl Descriptor {
    fn from_sddl(sddl: &str) -> io::Result<Descriptor> {
        let sddl: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Descriptor(descriptor))
    }

    fn dacl(&self) -> *mut ACL {
        let (mut present, mut defaulted) = (0, 0);
        let mut dacl: *mut ACL = ptr::null_mut();
        unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted) };
        dacl
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

fn create_private(path: &Path) -> io::Result<File> {
    let descriptor = Descriptor::from_sddl(PRIVATE)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
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
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a handle CreateFileW just opened, owned by nothing else.
    Ok(unsafe { File::from_raw_handle(handle) })
}

/// A file's owner and DACL, as `GetSecurityInfo` returns them; the pointers are into the
/// descriptor, which is freed on drop.
struct Security {
    descriptor: PSECURITY_DESCRIPTOR,
    owner: PSID,
    dacl: *mut ACL,
}

impl Security {
    fn of(file: &File) -> io::Result<Security> {
        let mut s = Security {
            descriptor: ptr::null_mut(),
            owner: ptr::null_mut(),
            dacl: ptr::null_mut(),
        };
        let code = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut s.owner,
                ptr::null_mut(),
                &mut s.dacl,
                ptr::null_mut(),
                &mut s.descriptor,
            )
        };
        if code != 0 {
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        Ok(s)
    }

    fn same_owner(&self, other: &Security) -> bool {
        !self.owner.is_null()
            && !other.owner.is_null()
            && unsafe { EqualSid(self.owner, other.owner) } != 0
    }

    /// Whether the DACL is the file's own rather than inherited from its directory.
    fn protected(&self) -> bool {
        let (mut control, mut revision) = (0u16, 0u32);
        unsafe { GetSecurityDescriptorControl(self.descriptor, &mut control, &mut revision) };
        control & SE_DACL_PROTECTED != 0
    }

    fn dacl_bytes(&self) -> Option<&[u8]> {
        if self.dacl.is_null() {
            return None;
        }
        let len = usize::from(unsafe { (*self.dacl).AclSize });
        Some(unsafe { std::slice::from_raw_parts(self.dacl.cast::<u8>(), len) })
    }
}

impl Drop for Security {
    fn drop(&mut self) {
        if !self.descriptor.is_null() {
            unsafe { LocalFree(self.descriptor) };
        }
    }
}

fn set_protected_dacl(file: &File, dacl: *const ACL) -> io::Result<()> {
    let code = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null(),
        )
    };
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}

/// Before anything is written to a replacement: the same owner, and the same ACL. A file whose
/// ACL is inherited from the directory gets the same from it as a new file there; one with its
/// own (protected) ACL gets a copy. Anything else can't be matched, so the save must overwrite in
/// place instead, and with `private_on_failure` the staged file becomes private to its owner,
/// since it's now only a copy to overwrite from and the original may have been closed to others.
pub(crate) fn prepare(
    staged: &File,
    original: &Original,
    private_on_failure: bool,
    failures: &mut Vec<Failure>,
) {
    if let Err(failure) = match_security(staged, original) {
        failures.push(failure);
        if private_on_failure {
            if let Ok(private) = Descriptor::from_sddl(PRIVATE) {
                let _ = set_protected_dacl(staged, private.dacl());
            }
        }
    }
}

fn match_security(staged: &File, original: &Original) -> Result<(), Failure> {
    let acl = |detail: String| Failure {
        lost: Lost::Acl,
        detail: format!("the access control list: {detail}"),
    };
    // The file being replaced: through the handle opened when the save began or, when another
    // save has replaced it since (that handle then reaches a deleted file), whatever is at the
    // path now, which is what this save will replace.
    let theirs = original
        .file
        .as_ref()
        .and_then(|file| Security::of(file).ok())
        .or_else(|| {
            let file = open_with(&original.path, READ_CONTROL).ok()?;
            Security::of(&file).ok()
        })
        .ok_or_else(|| acl("it can't be read".into()))?;
    let ours = Security::of(staged).map_err(|e| acl(e.to_string()))?;
    if !theirs.same_owner(&ours) {
        return Err(Failure {
            lost: Lost::Owner,
            detail: "the owner: a new file would belong to this user".into(),
        });
    }
    if theirs.dacl_bytes() == ours.dacl_bytes() {
        return Ok(());
    }
    if theirs.protected() && !theirs.dacl.is_null() {
        return set_protected_dacl(staged, theirs.dacl).map_err(|e| acl(e.to_string()));
    }
    Err(acl(
        "it has entries of its own that a new file wouldn't inherit".into(),
    ))
}

/// After the contents: the creation time, the attributes, and the alternate data streams.
pub(crate) fn copy_metadata(
    staged: &File,
    staged_path: &Path,
    original: &Original,
    failures: &mut Vec<Failure>,
) {
    let flags = |detail: String| Failure {
        lost: Lost::Flags,
        detail,
    };
    let Some(theirs) = original.info else {
        failures.push(flags("its attributes: they can't be read".into()));
        return;
    };
    let ours = match info(staged) {
        Ok(ours) => ours,
        Err(e) => {
            failures.push(flags(format!("its attributes: {e}")));
            return;
        }
    };
    if theirs.attributes & STORAGE_ATTRIBUTES != ours.attributes & STORAGE_ATTRIBUTES {
        failures.push(flags(
            "its compression or encryption, which a new file here doesn't get".into(),
        ));
    }
    let mut attributes =
        (ours.attributes & !KEPT_ATTRIBUTES) | (theirs.attributes & KEPT_ATTRIBUTES);
    if attributes == 0 {
        attributes = FILE_ATTRIBUTE_NORMAL;
    }
    // Zero leaves a time as it is.
    let basic = FILE_BASIC_INFO {
        CreationTime: theirs.creation as i64,
        LastAccessTime: 0,
        LastWriteTime: 0,
        ChangeTime: 0,
        FileAttributes: attributes,
    };
    let ok = unsafe {
        SetFileInformationByHandle(
            staged.as_raw_handle(),
            FileBasicInfo,
            (&basic as *const FILE_BASIC_INFO).cast::<c_void>(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    };
    if ok == 0 {
        failures.push(flags(format!(
            "its attributes and creation time: {}",
            io::Error::last_os_error()
        )));
    }
    copy_streams(&original.path, staged_path, failures);
}

/// Copies the named streams (`file:name`), such as the `Zone.Identifier` that marks a file as
/// downloaded. A file system without streams has none to copy.
fn copy_streams(from: &Path, to: &Path, failures: &mut Vec<Failure>) {
    // SAFETY: plain data, filled in by the calls.
    let mut data: WIN32_FIND_STREAM_DATA = unsafe { std::mem::zeroed() };
    let find = unsafe {
        FindFirstStreamW(
            wide(from).as_ptr(),
            FindStreamInfoStandard,
            (&mut data as *mut WIN32_FIND_STREAM_DATA).cast::<c_void>(),
            0,
        )
    };
    if find == INVALID_HANDLE_VALUE {
        return;
    }
    loop {
        let len = data
            .cStreamName
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(data.cStreamName.len());
        // ":name:$DATA"; the file's own contents are "::$DATA".
        let full = &data.cStreamName[..len];
        let suffix: Vec<u16> = ":$DATA".encode_utf16().collect();
        if let Some(name) = full.strip_suffix(suffix.as_slice()) {
            if name.len() > 1 {
                let name = OsString::from_wide(name);
                if let Err(e) = copy_stream(from, to, &name) {
                    let shown = name.to_string_lossy().trim_start_matches(':').to_string();
                    failures.push(Failure {
                        lost: Lost::Xattr(shown.clone()),
                        detail: format!("the alternate data stream {shown}: {e}"),
                    });
                }
            }
        }
        if unsafe {
            FindNextStreamW(
                find,
                (&mut data as *mut WIN32_FIND_STREAM_DATA).cast::<c_void>(),
            )
        } == 0
        {
            break;
        }
    }
    unsafe { FindClose(find) };
}

fn copy_stream(from: &Path, to: &Path, name: &OsStr) -> io::Result<()> {
    let with = |path: &Path| {
        let mut s = path.as_os_str().to_owned();
        s.push(name);
        PathBuf::from(s)
    };
    let mut source = File::open(with(from))?;
    let mut target = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(with(to))?;
    io::copy(&mut source, &mut target).map(drop)
}

/// Puts the staged file at the target. It's closed first, so on failure there's no handle to give
/// back; it can be opened again.
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
    drop(file);
    let moved = match put {
        Put::NewExclusive => move_file(staged, target, false, sync),
        Put::New | Put::OverFile | Put::OverLink => rename_over(staged, target, sync),
    };
    moved.map_err(|e| ReplaceError::new(e, None))?;
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

fn transient(e: &io::Error) -> bool {
    let codes = [
        ERROR_SHARING_VIOLATION,
        ERROR_LOCK_VIOLATION,
        ERROR_ACCESS_DENIED,
    ];
    e.raw_os_error()
        .is_some_and(|c| codes.contains(&(c as u32)))
}

/// Renames the staged file over the target in one step, so readers find the old file or the new
/// one, never neither. `MoveFileExW` does that unless the target is open; then std's rename falls
/// back to POSIX semantics, which allow it while others have the file open (if they let it be
/// deleted). Virus scanners, indexers and sync clients hold files briefly, so a refusal is retried
/// for about half a second.
fn rename_over(staged: &Path, target: &Path, sync: bool) -> io::Result<()> {
    let mut delay = Duration::from_millis(1);
    loop {
        let renamed = match move_file(staged, target, true, sync) {
            Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {
                fs::rename(staged, target).map(|()| {
                    if sync {
                        flush(target);
                    }
                })
            }
            other => other,
        };
        match renamed {
            Ok(()) => return Ok(()),
            Err(e) if transient(&e) && delay < Duration::from_millis(500) => {
                thread::sleep(delay);
                delay *= 2;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Best effort: the POSIX-semantics rename has no write-through option.
fn flush(target: &Path) {
    if let Ok(file) = OpenOptions::new().write(true).open(target) {
        let _ = file.sync_all();
    }
}

/// Any failure to replace, except the file having vanished, is worth an overwrite in place:
/// a lock that outlasted the retries, a file system that can't rename over a file.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// While other saves keep replacing the file, its ACL can still be matched: a new file in the
    /// same directory inherits the same one. Prints what went wrong if not.
    #[test]
    fn security_matches_while_others_replace_the_file() {
        let dir = std::env::temp_dir().join(format!("saveguard-unit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        let path = dir.join("a.txt");
        fs::write(&path, "start").unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let others: Vec<_> = (0..3)
            .map(|_| {
                let (path, stop) = (path.clone(), Arc::clone(&stop));
                thread::spawn(move || {
                    let mut opts = crate::Options::new();
                    opts.durability(crate::Durability::None)
                        .strategy(crate::Strategy::Replace);
                    while !stop.load(Ordering::Relaxed) {
                        let _ = opts.save(&path, "x");
                    }
                })
            })
            .collect();
        let mut failures = Vec::new();
        for _ in 0..300 {
            let Ok(Some(original)) = inspect(&path) else {
                continue;
            };
            let staged = create_staged(&dir, None, Stage::Replacement).unwrap();
            if let Err(failure) = match_security(&staged.file, &original) {
                failures.push(failure.detail);
            }
            drop(staged.file);
            let _ = fs::remove_file(&staged.path);
        }
        stop.store(true, Ordering::Relaxed);
        for t in others {
            t.join().unwrap();
        }
        let _ = fs::remove_dir_all(&dir);
        failures.sort();
        failures.dedup();
        assert!(failures.is_empty(), "{failures:#?}");
    }
}
