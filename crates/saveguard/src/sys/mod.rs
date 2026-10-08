//! The platform-specific half. Each platform provides the same functions:
//!
//! - `inspect(path)`: the existing file, if any, as an `Original` (with `is_file`, `is_symlink`,
//!   `facts`)
//! - `writable(path)`, `dir_writable(dir)`, `is_denied(error)`
//! - `create_staged(dir, mode)`: a new, empty, uniquely named file
//! - `prepare(staged, original, failures)`: what must be copied before any data is written
//! - `copy_metadata(staged, original, failures)`: what is copied after
//! - `replace(staged_file, staged, target, put, sync)`: puts the staged file at the target
//! - `rename_refused(error)`: whether a failed replace should fall back to overwriting
//! - `overwrite(staged, target, len, sync)`: copies the staged contents into the target
//! - `stamp_of(file)`, `stamp_at(path)`: what a `Version` compares

use std::collections::hash_map::RandomState;
use std::fs::File;
use std::hash::{BuildHasher, Hasher};
use std::io;
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
    /// What a forced replace loses because of it, if anything can be named.
    pub lost: Option<Lost>,
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

/// A fresh name for a staged file. Hidden on Unix, and unlikely to collide; creation uses
/// `create_new`, and a collision just means another try.
pub(crate) fn temp_name() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    // RandomState is seeded from the operating system's random source.
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    hasher.write_u32(std::process::id());
    format!(".saveguard-{:016x}.tmp", hasher.finish())
}
