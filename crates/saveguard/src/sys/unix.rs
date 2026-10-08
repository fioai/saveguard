//! Linux, macOS and other Unix systems. Extended attributes and file flags are handled on Linux
//! and Apple systems; the rest works on any Unix.

use std::ffi::{CStr, CString, OsStr};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Seek, SeekFrom};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;

use super::{Facts, Failure, OverwriteError, Put, ReplaceError, Stage, Staged};
use crate::version::Stamp;
use crate::Lost;

/// The file being saved over, as it was when the save started.
pub(crate) struct Original {
    meta: Metadata,
    /// Open for reading, to copy extended attributes and flags from. `None` when it can't be
    /// opened, and for anything that isn't a regular file.
    file: Option<File>,
    mount_point: bool,
}

impl Original {
    pub fn is_file(&self) -> bool {
        self.meta.file_type().is_file()
    }

    pub fn is_symlink(&self) -> bool {
        self.meta.file_type().is_symlink()
    }

    pub fn facts(&self) -> Facts {
        let root = is_root();
        let mode = self.meta.mode() & 0o7777;
        Facts {
            links: self.meta.nlink(),
            mount_point: self.mount_point,
            owner_kept: root || self.meta.uid() == unsafe { libc::geteuid() },
            // When it can't be told, try: copying the group fails if it can't be done.
            group_kept: root || in_group(self.meta.gid()) != Some(false),
            setid: kept_mode(mode, self.meta.gid()) != mode,
            capabilities: has_capabilities(self.file.as_ref()),
        }
    }

    /// See [`trusted`].
    pub fn trusted(&self, path: &Path) -> bool {
        trusted(path, &self.meta)
    }
}

/// The kernel's rule for sticky, world-writable directories such as `/tmp`
/// (`fs.protected_symlinks`, `fs.protected_regular`): a symlink or file in one may only be
/// followed or written by its owner, or if it belongs to the directory's owner. Otherwise another
/// user could plant a link there and choose what a save overwrites. Following symlinks by hand, as
/// `resolve` does, skips the kernel's check, so it's made here, on every Unix.
pub(crate) fn trusted(path: &Path, meta: &Metadata) -> bool {
    let Ok(dir) = fs::metadata(dir_of(path)) else {
        return true; // nothing to go on; the save itself will fail
    };
    let mode = dir.mode();
    if mode & STICKY == 0 || mode & OTHERS_WRITE == 0 {
        return true;
    }
    meta.uid() == unsafe { libc::geteuid() } || meta.uid() == dir.uid()
}

pub(crate) fn inspect(path: &Path) -> io::Result<Option<Original>> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if !meta.file_type().is_file() {
        return Ok(Some(Original {
            meta,
            file: None,
            mount_point: false,
        }));
    }
    // Non-blocking, in case a FIFO is swapped in after the look: opening one would wait forever.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok();
    // Prefer what the open file says, so the metadata and the handle are the same file.
    let meta = file
        .as_ref()
        .and_then(|f| f.metadata().ok())
        .unwrap_or(meta);
    let mount_point = is_mount_point(path, &meta);
    Ok(Some(Original {
        meta,
        file,
        mount_point,
    }))
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Whether this process is in the group: `None` when it can't be told, because macOS's
/// `getgroups` stops at 16 groups.
fn in_group(gid: u32) -> Option<bool> {
    if unsafe { libc::getegid() } == gid {
        return Some(true);
    }
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if n < 0 {
        return None;
    }
    let mut groups = vec![0 as libc::gid_t; n.max(1) as usize];
    let n = unsafe { libc::getgroups(n, groups.as_mut_ptr()) };
    if n < 0 {
        return None;
    }
    let found = groups[..n as usize].contains(&gid);
    if !found && cfg!(target_vendor = "apple") && n >= 16 {
        return None;
    }
    Some(found)
}

/// The permissions a file keeps when its contents change, by the kernel's rule for a write in place
/// (`setattr_should_drop_suidgid` in Linux's `fs/attr.c`): unless the writer may keep them, setuid
/// is cleared, and setgid too if the file is group-executable or the writer isn't in its group. A
/// replacement does the same rather than carry privileges over to contents nobody vetted.
fn kept_mode(mode: u32, gid: u32) -> u32 {
    let mode = mode & 0o7777;
    if mode & (SETUID | SETGID) == 0 || retains_setid() {
        return mode;
    }
    let mut kept = mode & !SETUID;
    if kept & SETGID != 0 && (kept & GROUP_EXEC != 0 || in_group(gid) == Some(false)) {
        kept &= !SETGID;
    }
    kept
}

/// Linux keeps the bits when the writer has `CAP_FSETID` in the *initial* user namespace
/// (`capable()`): root in a container's own user namespace doesn't count.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn retains_setid() -> bool {
    const CAP_FSETID: u32 = 4;
    // PROC_USER_INIT_INO: the initial user namespace's inode number, fixed in the kernel.
    const INIT_USER_NS: u64 = 0xEFFF_FFFD;
    let Ok(ns) = fs::metadata("/proc/self/ns/user") else {
        return is_root();
    };
    if ns.ino() != INIT_USER_NS {
        return false;
    }
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return is_root();
    };
    status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|caps| u64::from_str_radix(caps.trim(), 16).ok())
        .map_or_else(is_root, |caps| caps & (1 << CAP_FSETID) != 0)
}

/// Elsewhere, root keeps them.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn retains_setid() -> bool {
    is_root()
}

// mode_t is 16 bits on macOS and 32 elsewhere.
#[allow(clippy::unnecessary_cast)]
const SETUID: u32 = libc::S_ISUID as u32;
#[allow(clippy::unnecessary_cast)]
const SETGID: u32 = libc::S_ISGID as u32;
#[allow(clippy::unnecessary_cast)]
const GROUP_EXEC: u32 = libc::S_IXGRP as u32;
#[allow(clippy::unnecessary_cast)]
const STICKY: u32 = libc::S_ISVTX as u32;
#[allow(clippy::unnecessary_cast)]
const OTHERS_WRITE: u32 = libc::S_IWOTH as u32;

/// Whether the file is itself a mount point, like a single file bind-mounted into a container.
///
/// A bind mount from the same file system has the same device number as the directory it's in, so
/// comparing devices doesn't find it; `statx` reports it directly (Linux 5.8 and later).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn is_mount_point(path: &Path, meta: &Metadata) -> bool {
    if let Some(root) = statx_mount_root(path) {
        return root;
    }
    differs_from_parent(path, meta)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn is_mount_point(path: &Path, meta: &Metadata) -> bool {
    differs_from_parent(path, meta)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn statx_mount_root(path: &Path) -> Option<bool> {
    let c = cstr(path).ok()?;
    // SAFETY: statx fills in the struct, which is plain data that may start zeroed.
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    let r = unsafe {
        libc::statx(
            libc::AT_FDCWD,
            c.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
            libc::STATX_TYPE,
            &mut stx,
        )
    };
    let bit = libc::STATX_ATTR_MOUNT_ROOT as u64;
    if r != 0 || stx.stx_attributes_mask & bit == 0 {
        return None;
    }
    Some(stx.stx_attributes & bit != 0)
}

/// A different device than the directory's means a mount of another file system.
fn differs_from_parent(path: &Path, meta: &Metadata) -> bool {
    fs::metadata(dir_of(path)).is_ok_and(|dir| dir.dev() != meta.dev())
}

fn dir_of(path: &Path) -> &Path {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    }
}

fn cstr(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "the path contains a NUL byte"))
}

fn denied(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(c) if c == libc::EACCES || c == libc::EPERM || c == libc::EROFS)
}

pub(crate) fn is_denied(e: &io::Error) -> bool {
    denied(e)
}

/// `access(2)` with the effective user, which is who the writes will be made as.
fn access(path: &Path, mode: libc::c_int) -> io::Result<()> {
    let c = cstr(path)?;
    #[cfg(any(target_os = "linux", target_vendor = "apple", target_os = "freebsd"))]
    let r = unsafe { libc::faccessat(libc::AT_FDCWD, c.as_ptr(), mode, libc::AT_EACCESS) };
    #[cfg(not(any(target_os = "linux", target_vendor = "apple", target_os = "freebsd")))]
    let r = unsafe { libc::access(c.as_ptr(), mode) };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(crate) fn writable(path: &Path) -> io::Result<bool> {
    match access(path, libc::W_OK) {
        Ok(()) => Ok(true),
        Err(e) if denied(&e) => Ok(false),
        Err(e) => Err(e),
    }
}

pub(crate) fn dir_writable(dir: &Path) -> bool {
    access(dir, libc::W_OK | libc::X_OK).is_ok()
}

/// A new, empty file in `dir`, with the mode for a [`Stage::New`] file (less the umask), or
/// private to this user (`0600`).
pub(crate) fn create_staged(dir: &Path, name: Option<&OsStr>, stage: Stage) -> io::Result<Staged> {
    let mode = match stage {
        Stage::New(mode) => mode,
        Stage::Replacement | Stage::Copy => 0o600,
    };
    let mut collisions = 0;
    loop {
        let path = dir.join(super::temp_name(name));
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(mode)
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

/// Copies what has to be set while the staged file is still empty. (It's private until the end
/// anyway, so `private_on_failure` has nothing to do here.)
pub(crate) fn prepare(
    staged: &File,
    original: &Original,
    _private_on_failure: bool,
    failures: &mut Vec<Failure>,
) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(from) = &original.file {
        linux::copy_flags(from, staged, failures);
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let _ = (staged, original, failures);
}

/// Gives the staged file the original's extended attributes (including the ACL and security label
/// on Linux), ACL (macOS), owner, group, permissions and flags. Whatever won't copy is added to
/// `failures`.
pub(crate) fn copy_metadata(
    staged: &File,
    _staged_path: &Path,
    original: &Original,
    failures: &mut Vec<Failure>,
) {
    match &original.file {
        Some(from) => copy_xattrs(from, staged, failures),
        None => failures.push(Failure {
            lost: Lost::UnreadableXattrs,
            detail: "its extended attributes: the file can't be opened for reading".into(),
        }),
    }
    #[cfg(target_vendor = "apple")]
    if let Some(from) = &original.file {
        apple::copy_acl(from, staged, failures);
    }
    copy_owner(staged, &original.meta, failures);
    copy_mode(staged, &original.meta, failures);
    #[cfg(target_vendor = "apple")]
    {
        if let Some(from) = &original.file {
            apple::copy_flags(from, staged, failures);
        }
        apple::copy_creation_time(&original.meta, staged);
    }
}

fn copy_owner(staged: &File, meta: &Metadata, failures: &mut Vec<Failure>) {
    let now = match staged.metadata() {
        Ok(now) => now,
        Err(e) => {
            failures.push(Failure {
                lost: Lost::Owner,
                detail: format!("the owner: {e}"),
            });
            return;
        }
    };
    let (uid, gid) = (meta.uid(), meta.gid());
    if now.uid() == uid && now.gid() == gid {
        return;
    }
    let fd = staged.as_raw_fd();
    if unsafe { libc::fchown(fd, uid, gid) } == 0 {
        return;
    }
    let e = io::Error::last_os_error();
    if now.uid() != uid {
        failures.push(Failure {
            lost: Lost::Owner,
            detail: format!("the owner: {e}"),
        });
    }
    // The group may still be possible alone (-1 leaves the owner as it is).
    if now.gid() != gid && unsafe { libc::fchown(fd, libc::uid_t::MAX, gid) } != 0 {
        failures.push(Failure {
            lost: Lost::Group,
            detail: format!("the group: {}", io::Error::last_os_error()),
        });
    }
}

/// After the owner: changing the owner clears setuid and setgid.
fn copy_mode(staged: &File, meta: &Metadata, failures: &mut Vec<Failure>) {
    let mode = kept_mode(meta.mode(), meta.gid());
    if staged
        .metadata()
        .is_ok_and(|now| now.mode() & 0o7777 == mode)
    {
        return;
    }
    if unsafe { libc::fchmod(staged.as_raw_fd(), mode as libc::mode_t) } != 0 {
        failures.push(Failure {
            lost: Lost::Permissions,
            detail: format!("the permissions: {}", io::Error::last_os_error()),
        });
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn copy_xattrs(from: &File, to: &File, failures: &mut Vec<Failure>) {
    let (src, dst) = (from.as_raw_fd(), to.as_raw_fd());
    let names = match xattr::list(src) {
        Ok(names) => names,
        Err(e) => {
            failures.push(Failure {
                lost: Lost::UnreadableXattrs,
                detail: format!("its extended attributes: {e}"),
            });
            return;
        }
    };
    for name in &names {
        if !worth_copying(name) {
            continue;
        }
        match xattr::get(src, name) {
            // Setting a value it already has (a security label the directory gave it) can still
            // need permission, so don't.
            Ok(Some(value)) if xattr::get(dst, name).ok().flatten().as_ref() == Some(&value) => {}
            Ok(Some(value)) => {
                if let Err(e) = xattr::set(dst, name, &value) {
                    failures.push(xattr_failure(name, &e));
                }
            }
            Ok(None) => {} // removed in the meantime
            Err(e) => failures.push(xattr_failure(name, &e)),
        }
    }
    // Take away what the new file was given that the old one doesn't have, such as an ACL
    // inherited from the directory's default ACL.
    if let Ok(extra) = xattr::list(dst) {
        for name in extra.iter().filter(|n| !names.contains(n) && removable(n)) {
            if let Err(e) = xattr::remove(dst, name) {
                failures.push(xattr_failure(name, &e));
            }
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn copy_xattrs(_from: &File, _to: &File, _failures: &mut Vec<Failure>) {}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn xattr_failure(name: &CStr, e: &io::Error) -> Failure {
    let lost = lost_xattr(name);
    let what = match &lost {
        Lost::Acl => "the access control list".to_string(),
        Lost::SecurityLabel => "the security label".to_string(),
        _ => format!("extended attribute {}", name.to_string_lossy()),
    };
    Failure {
        lost,
        detail: format!("{what}: {e}"),
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn lost_xattr(name: &CStr) -> Lost {
    match name.to_bytes() {
        b"system.posix_acl_access" => Lost::Acl,
        b"security.selinux" | b"security.SMACK64" => Lost::SecurityLabel,
        _ => Lost::Xattr(name.to_string_lossy().into_owned()),
    }
}

/// Linux: capabilities are cleared by the kernel whenever the contents change (and reported as
/// lost), and IMA and EVM hold hashes of the old file, which the kernel recomputes.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn worth_copying(name: &CStr) -> bool {
    !matches!(
        name.to_bytes(),
        b"security.capability" | b"security.ima" | b"security.evm"
    )
}

/// macOS says itself which attributes survive a safe save: not the ones that describe the old
/// contents, for example.
#[cfg(target_vendor = "apple")]
fn worth_copying(name: &CStr) -> bool {
    apple::keep_on_save(name)
}

/// Security labels are the system's to set.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn removable(name: &CStr) -> bool {
    !name.to_bytes().starts_with(b"security.")
}

/// The system's own attributes (quarantine, provenance, sandbox grants) are the system's to set.
#[cfg(target_vendor = "apple")]
fn removable(name: &CStr) -> bool {
    !name.to_bytes().starts_with(b"com.apple.")
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn has_capabilities(file: Option<&File>) -> bool {
    file.is_some_and(|f| xattr::has(f.as_raw_fd(), c"security.capability"))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn has_capabilities(_file: Option<&File>) -> bool {
    false
}

/// Puts the staged file at the target. On failure the staged file is handed back, still open, for
/// an overwrite in place: by then it may have the original's permissions, which needn't let it be
/// opened again.
pub(crate) fn replace(
    file: File,
    staged: &Path,
    target: &Path,
    put: Put,
    sync: bool,
) -> Result<Stamp, ReplaceError> {
    // A rename doesn't change the file's own metadata, so this is its version afterwards too.
    let stamp = match stamp_of(&file) {
        Ok(stamp) => stamp,
        Err(e) => return Err(ReplaceError::new(e, Some(file))),
    };
    let renamed = match put {
        Put::NewExclusive => rename_noreplace(staged, target),
        Put::New | Put::OverFile | Put::OverLink => fs::rename(staged, target),
    };
    if let Err(e) = renamed {
        return Err(ReplaceError::new(e, Some(file)));
    }
    drop(file);
    if sync {
        sync_dir(dir_of(target));
    }
    Ok(stamp)
}

/// Renames without replacing anything: fails with `AlreadyExists` if `to` exists.
fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    let (f, t) = (cstr(from)?, cstr(to)?);
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        const RENAME_NOREPLACE: libc::c_uint = 1;
        let r = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                f.as_ptr(),
                libc::AT_FDCWD,
                t.as_ptr(),
                RENAME_NOREPLACE,
            )
        };
        if r == 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        let unsupported = [libc::EINVAL, libc::ENOSYS, libc::ENOTSUP, libc::EOPNOTSUPP];
        if !e.raw_os_error().is_some_and(|c| unsupported.contains(&c)) {
            return Err(e);
        }
    }
    #[cfg(target_vendor = "apple")]
    {
        if unsafe { libc::renamex_np(f.as_ptr(), t.as_ptr(), libc::RENAME_EXCL) } == 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        let unsupported = [libc::EINVAL, libc::ENOTSUP, libc::EOPNOTSUPP];
        if !e.raw_os_error().is_some_and(|c| unsupported.contains(&c)) {
            return Err(e);
        }
    }
    // A hard link can't be made over an existing file either.
    if unsafe { libc::link(f.as_ptr(), t.as_ptr()) } == 0 {
        unsafe { libc::unlink(f.as_ptr()) };
        return Ok(());
    }
    let e = io::Error::last_os_error();
    if e.kind() == io::ErrorKind::AlreadyExists {
        return Err(e);
    }
    // No hard links on this file system (FAT, some FUSE ones): look, then rename, which leaves a
    // short window for another process.
    if fs::symlink_metadata(to).is_ok() {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    fs::rename(from, to)
}

/// Whether a replace that failed with `e` should be retried as an overwrite in place: a mount
/// point (`EBUSY`), a different file system (`EXDEV`), or a rename that isn't allowed or supported.
pub(crate) fn rename_refused(e: &io::Error) -> bool {
    let refusals = [
        libc::EBUSY,
        libc::EXDEV,
        libc::EPERM,
        libc::EACCES,
        libc::EROFS,
        libc::EINVAL,
        libc::ENOTSUP,
        libc::EOPNOTSUPP,
    ];
    e.raw_os_error().is_some_and(|c| refusals.contains(&c))
}

/// Opens the file to be overwritten, if it's still the file inspected when the save began, and
/// locks it. `None` if something else is at the path now: a path can be made to lead elsewhere in
/// between (a directory swapped for a symlink), and the inspection is what the decision rests on.
/// The lock (`flock`) makes two saveguard saves that overwrite the same file take turns, rather
/// than interleave their writes; other programs aren't affected.
pub(crate) fn open_existing(target: &Path, original: &Original) -> io::Result<Option<File>> {
    let file = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(target)?;
    let meta = file.metadata()?;
    if meta.dev() != original.meta.dev() || meta.ino() != original.meta.ino() {
        return Ok(None);
    }
    let no_locks = [libc::ENOLCK, libc::ENOSYS, libc::EOPNOTSUPP, libc::EINVAL];
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            break;
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(c) if no_locks.contains(&c) => break, // no locks here: carry on without
            _ => return Err(e),
        }
    }
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
    reserve(to, len).map_err(before)?;
    io::copy(from, to).map_err(after)?;
    to.set_len(len).map_err(after)?;
    if sync {
        to.sync_all().map_err(after)?;
    }
    stamp_of(to).map_err(after)
}

/// Makes sure there's room for a file that grows, so that a full disk is found before anything
/// is overwritten rather than halfway through.
#[cfg(target_os = "linux")]
fn reserve(file: &File, len: u64) -> io::Result<()> {
    if len <= file.metadata()?.len() {
        return Ok(());
    }
    let Ok(len) = libc::off_t::try_from(len) else {
        return Ok(());
    };
    let r = unsafe { libc::fallocate(file.as_raw_fd(), libc::FALLOC_FL_KEEP_SIZE, 0, len) };
    if r == 0 {
        return Ok(());
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error()
        .is_some_and(|c| c == libc::ENOSPC || c == libc::EDQUOT)
    {
        Err(e)
    } else {
        Ok(()) // not supported here: just write
    }
}

#[cfg(not(target_os = "linux"))]
fn reserve(_file: &File, _len: u64) -> io::Result<()> {
    Ok(())
}

/// Flushes a directory, so a rename in it survives a crash. Some file systems can't, and by now
/// the save has happened, so failures are ignored.
fn sync_dir(dir: &Path) {
    if let Ok(dir) = File::open(dir) {
        let _ = dir.sync_all();
    }
}

pub(crate) fn stamp_of(file: &File) -> io::Result<Stamp> {
    Ok(stamp(&file.metadata()?))
}

pub(crate) fn stamp_at(path: &Path) -> io::Result<Option<Stamp>> {
    match fs::metadata(path) {
        Ok(meta) => Ok(Some(stamp(&meta))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn stamp(meta: &Metadata) -> Stamp {
    Stamp {
        dev: meta.dev(),
        ino: meta.ino(),
        size: meta.len(),
        mtime: meta
            .mtime()
            .saturating_mul(1_000_000_000)
            .saturating_add(meta.mtime_nsec()),
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
mod xattr {
    use std::ffi::{CStr, CString};
    use std::io;
    use std::os::unix::io::RawFd;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    mod raw {
        use libc::{c_char, c_int, c_void};
        use std::os::unix::io::RawFd;

        pub const NO_ATTR: c_int = libc::ENODATA;

        pub unsafe fn list(fd: RawFd, buf: *mut c_char, size: usize) -> isize {
            libc::flistxattr(fd, buf, size)
        }
        pub unsafe fn get(fd: RawFd, name: *const c_char, buf: *mut c_void, size: usize) -> isize {
            libc::fgetxattr(fd, name, buf, size)
        }
        pub unsafe fn set(
            fd: RawFd,
            name: *const c_char,
            value: *const c_void,
            size: usize,
        ) -> c_int {
            libc::fsetxattr(fd, name, value, size, 0)
        }
        pub unsafe fn remove(fd: RawFd, name: *const c_char) -> c_int {
            libc::fremovexattr(fd, name)
        }
    }

    #[cfg(target_vendor = "apple")]
    mod raw {
        use libc::{c_char, c_int, c_void};
        use std::os::unix::io::RawFd;

        pub const NO_ATTR: c_int = libc::ENOATTR;

        pub unsafe fn list(fd: RawFd, buf: *mut c_char, size: usize) -> isize {
            libc::flistxattr(fd, buf, size, 0)
        }
        pub unsafe fn get(fd: RawFd, name: *const c_char, buf: *mut c_void, size: usize) -> isize {
            libc::fgetxattr(fd, name, buf, size, 0, 0)
        }
        pub unsafe fn set(
            fd: RawFd,
            name: *const c_char,
            value: *const c_void,
            size: usize,
        ) -> c_int {
            libc::fsetxattr(fd, name, value, size, 0, 0)
        }
        pub unsafe fn remove(fd: RawFd, name: *const c_char) -> c_int {
            libc::fremovexattr(fd, name, 0)
        }
    }

    fn unsupported(e: &io::Error) -> bool {
        e.raw_os_error()
            .is_some_and(|c| c == libc::ENOTSUP || c == libc::EOPNOTSUPP)
    }

    /// The names of the file's extended attributes; none where the file system has none.
    pub fn list(fd: RawFd) -> io::Result<Vec<CString>> {
        loop {
            let size = unsafe { raw::list(fd, std::ptr::null_mut(), 0) };
            if size < 0 {
                let e = io::Error::last_os_error();
                return if unsupported(&e) {
                    Ok(Vec::new())
                } else {
                    Err(e)
                };
            }
            if size == 0 {
                return Ok(Vec::new());
            }
            let mut buf = vec![0u8; size as usize];
            let n = unsafe { raw::list(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::ERANGE) {
                    continue; // grew in the meantime
                }
                return Err(e);
            }
            buf.truncate(n as usize);
            return Ok(buf
                .split(|&b| b == 0)
                .filter(|name| !name.is_empty())
                .filter_map(|name| CString::new(name).ok())
                .collect());
        }
    }

    /// The attribute's value, or `None` if it isn't there.
    pub fn get(fd: RawFd, name: &CStr) -> io::Result<Option<Vec<u8>>> {
        loop {
            let size = unsafe { raw::get(fd, name.as_ptr(), std::ptr::null_mut(), 0) };
            if size < 0 {
                let e = io::Error::last_os_error();
                return if e.raw_os_error() == Some(raw::NO_ATTR) {
                    Ok(None)
                } else {
                    Err(e)
                };
            }
            let mut buf = vec![0u8; size as usize];
            let n = unsafe { raw::get(fd, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                let e = io::Error::last_os_error();
                match e.raw_os_error() {
                    Some(libc::ERANGE) => continue,
                    Some(c) if c == raw::NO_ATTR => return Ok(None),
                    _ => return Err(e),
                }
            }
            buf.truncate(n as usize);
            return Ok(Some(buf));
        }
    }

    pub fn set(fd: RawFd, name: &CStr, value: &[u8]) -> io::Result<()> {
        if unsafe { raw::set(fd, name.as_ptr(), value.as_ptr().cast(), value.len()) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn remove(fd: RawFd, name: &CStr) -> io::Result<()> {
        if unsafe { raw::remove(fd, name.as_ptr()) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn has(fd: RawFd, name: &CStr) -> bool {
        unsafe { raw::get(fd, name.as_ptr(), std::ptr::null_mut(), 0) >= 0 }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux {
    use std::fs::File;
    use std::io;
    use std::os::unix::io::AsRawFd;

    use libc::c_int;

    use crate::sys::Failure;
    use crate::Lost;

    // From <linux/fs.h>: the flags worth keeping. Not the ones the file system manages itself
    // (extents, inline data, encryption, verity), nor immutable and append-only, which stop any
    // save. Some need privilege to set (data journaling); then Auto overwrites in place.
    const FS_SECRM_FL: c_int = 0x0000_0001;
    const FS_UNRM_FL: c_int = 0x0000_0002;
    const FS_COMPR_FL: c_int = 0x0000_0004;
    const FS_SYNC_FL: c_int = 0x0000_0008;
    const FS_NODUMP_FL: c_int = 0x0000_0040;
    const FS_NOATIME_FL: c_int = 0x0000_0080;
    const FS_NOCOMP_FL: c_int = 0x0000_0400;
    const FS_JOURNAL_DATA_FL: c_int = 0x0000_4000;
    const FS_NOCOW_FL: c_int = 0x0080_0000;
    const COPIED: c_int = FS_SECRM_FL
        | FS_UNRM_FL
        | FS_COMPR_FL
        | FS_SYNC_FL
        | FS_NODUMP_FL
        | FS_NOATIME_FL
        | FS_NOCOMP_FL
        | FS_JOURNAL_DATA_FL
        | FS_NOCOW_FL;

    fn get(file: &File) -> io::Result<c_int> {
        let mut flags: c_int = 0;
        // The kernel reads and writes an int, whatever the ioctl's declared size.
        if unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut flags) } == 0 {
            Ok(flags)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn set(file: &File, flags: c_int) -> io::Result<()> {
        if unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_SETFLAGS, &flags) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// The `chattr` flags. No-copy-on-write (btrfs) only takes on an empty file, so this runs
    /// before anything is written.
    pub fn copy_flags(from: &File, to: &File, failures: &mut Vec<Failure>) {
        let Ok(original) = get(from) else {
            return; // a file system without flags
        };
        let wanted = original & COPIED;
        let current = match get(to) {
            Ok(current) => current,
            Err(e) => {
                if wanted != 0 {
                    failures.push(failure(&e));
                }
                return;
            }
        };
        if current & COPIED != wanted {
            if let Err(e) = set(to, (current & !COPIED) | wanted) {
                failures.push(failure(&e));
            }
        }
    }

    fn failure(e: &io::Error) -> Failure {
        Failure {
            lost: Lost::Flags,
            detail: format!("its file flags: {e}"),
        }
    }
}

#[cfg(target_vendor = "apple")]
mod apple {
    use std::ffi::CStr;
    use std::fs::{File, Metadata};
    use std::io;
    use std::os::unix::io::AsRawFd;
    use std::time::UNIX_EPOCH;

    use libc::{c_char, c_int};

    use crate::sys::Failure;
    use crate::Lost;

    // <xattr_flags.h>, macOS 10.10 and later.
    const XATTR_OPERATION_INTENT_SAVE: u32 = 2;
    extern "C" {
        fn xattr_preserve_for_intent(name: *const c_char, intent: u32) -> c_int;
    }

    pub fn keep_on_save(name: &CStr) -> bool {
        unsafe { xattr_preserve_for_intent(name.as_ptr(), XATTR_OPERATION_INTENT_SAVE) != 0 }
    }

    pub fn copy_acl(from: &File, to: &File, failures: &mut Vec<Failure>) {
        let r = unsafe {
            libc::fcopyfile(
                from.as_raw_fd(),
                to.as_raw_fd(),
                std::ptr::null_mut(),
                libc::COPYFILE_ACL,
            )
        };
        if r != 0 {
            failures.push(Failure {
                lost: Lost::Acl,
                detail: format!("the access control list: {}", io::Error::last_os_error()),
            });
        }
    }

    const COPIED_FLAGS: u32 = libc::UF_NODUMP | libc::UF_HIDDEN;

    fn flags(file: &File) -> io::Result<u32> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(file.as_raw_fd(), &mut st) } == 0 {
            Ok(st.st_flags)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// The `chflags` flags the owner can set: hidden and no-dump.
    pub fn copy_flags(from: &File, to: &File, failures: &mut Vec<Failure>) {
        let (Ok(original), Ok(current)) = (flags(from), flags(to)) else {
            return;
        };
        let wanted = original & COPIED_FLAGS;
        if current & COPIED_FLAGS == wanted {
            return;
        }
        if unsafe { libc::fchflags(to.as_raw_fd(), (current & !COPIED_FLAGS) | wanted) } != 0 {
            failures.push(Failure {
                lost: Lost::Flags,
                detail: format!("its file flags: {}", io::Error::last_os_error()),
            });
        }
    }

    /// The Finder shows when a file was created; keep that. Best effort: a failure isn't reported.
    pub fn copy_creation_time(meta: &Metadata, to: &File) {
        let Ok(created) = meta.created() else { return };
        let Ok(since) = created.duration_since(UNIX_EPOCH) else {
            return;
        };
        let mut time = libc::timespec {
            tv_sec: since.as_secs() as libc::time_t,
            tv_nsec: since.subsec_nanos() as libc::c_long,
        };
        let mut list = libc::attrlist {
            bitmapcount: libc::ATTR_BIT_MAP_COUNT,
            reserved: 0,
            commonattr: libc::ATTR_CMN_CRTIME,
            volattr: 0,
            dirattr: 0,
            fileattr: 0,
            forkattr: 0,
        };
        unsafe {
            libc::fsetattrlist(
                to.as_raw_fd(),
                (&mut list as *mut libc::attrlist).cast(),
                (&mut time as *mut libc::timespec).cast(),
                std::mem::size_of::<libc::timespec>(),
                0,
            )
        };
    }
}
