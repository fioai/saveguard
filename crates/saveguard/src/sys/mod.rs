//! The platform-specific half. Each platform provides the same functions:
//!
//! - `inspect(path)`: the existing file, if any, as an `Original` (with `is_file`, `is_symlink`,
//!   `facts`)
//! - `writable(path)`, `dir_writable(dir)`, `is_denied(error)`
//! - `create_staged(dir, name, mode)`: a new, empty, uniquely named file; `mode` `None` means
//!   private to this user, for contents replacing an existing file
//! - `prepare(staged, original, failures)`: what must be copied before any data is written
//! - `copy_metadata(staged, original, failures)`: what is copied after
//! - `replace(staged_file, staged, target, put, sync)`: puts the staged file at the target
//! - `rename_refused(error)`: whether a failed replace should fall back to overwriting
//! - `open_existing(target, original)`: opens the target for an overwrite, if it's still the
//!   inspected file, and locks it
//! - `overwrite(staged_file, target_file, len, sync)`: copies the staged contents into the target
//! - `stamp_of(file)`, `stamp_at(path)`: what a `Version` compares

use std::collections::hash_map::RandomState;
use std::ffi::OsStr;
use std::fs::File;
use std::hash::{BuildHasher, Hasher};
use std::io;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::Lost;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub(crate) use unix::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::*;

/// What the decision between replacing and overwriting needs to know about an existing file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Facts {
    /// How many names (hard links) the file has.
    pub links: u64,
    /// Whether the file is itself a mount point, which a rename can't replace.
    pub mount_point: bool,
    /// Whether a new file can be given the file's owner.
    pub owner_kept: bool,
    /// Whether a new file can be given the file's group.
    pub group_kept: bool,
    /// Whether the file has setuid/setgid bits that changing its contents clears.
    pub setid: bool,
    /// Whether the file has Linux file capabilities, which changing its contents clears.
    pub capabilities: bool,
}

/// Something about the original that couldn't be given to the staged file.
#[derive(Clone, Debug)]
pub(crate) struct Failure {
    /// What a forced replace loses because of it.
    pub lost: Lost,
    /// For the report, e.g. "extended attribute user.x: Permission denied".
    pub detail: String,
}

/// The file the new contents are written to before they are put in place.
pub(crate) struct Staged {
    pub file: File,
    pub path: PathBuf,
}

/// How the staged file is put at the target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Put {
    /// Nothing was there.
    New,
    /// Nothing was there, and if something is now, fail with `AlreadyExists`.
    NewExclusive,
    /// Over an existing regular file.
    OverFile,
    /// Over a symlink, which is replaced itself.
    OverLink,
}

/// An overwrite in place that failed, and whether it got as far as changing the target.
pub(crate) struct OverwriteError {
    pub touched: bool,
    pub error: io::Error,
}

/// A replace that failed.
pub(crate) struct ReplaceError {
    pub error: io::Error,
    /// The staged file, still open, where the platform could keep it open.
    pub file: Option<File>,
    /// Set when the replace got partway and couldn't be undone: the old contents are at this path
    /// and the target may be missing. Nothing more may be tried, and the staged file must be kept.
    pub stranded: Option<PathBuf>,
}

impl ReplaceError {
    pub fn new(error: io::Error, file: Option<File>) -> ReplaceError {
        ReplaceError {
            error,
            file,
            stranded: None,
        }
    }
}

/// A fresh name for a staged file, with the target's name in it so that a copy left by a crash
/// can be recognised. Hidden on Unix, and unlikely to collide; creation uses `create_new`, and a
/// collision just means another try.
pub(crate) fn temp_name(target: Option<&OsStr>) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    // RandomState is seeded from the operating system's random source.
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    hasher.write_u32(std::process::id());
    let mut name = String::new();
    // At most 64 bytes of it, so the whole name stays well within any file system's limit.
    for c in target
        .map(|t| t.to_string_lossy())
        .unwrap_or_default()
        .chars()
    {
        if name.len() + c.len_utf8() > 64 {
            break;
        }
        name.push(c);
    }
    format!(".saveguard-{name}-{:016x}.tmp", hasher.finish())
}

/// Where the new contents are staged when the target's own directory won't take them. It has to
/// survive a reboot, since after a crash during an overwrite in place it holds the only complete
/// copy of them: `/var/tmp` rather than `/tmp`, which is often in memory or cleared at boot.
pub(crate) fn fallback_dir() -> PathBuf {
    #[cfg(unix)]
    {
        let var_tmp = Path::new("/var/tmp");
        if var_tmp.is_dir() {
            return var_tmp.to_path_buf();
        }
    }
    std::env::temp_dir()
}
