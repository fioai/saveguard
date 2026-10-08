use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

/// The result of a saveguard operation.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Why a save failed.
///
/// Unless the variant says otherwise, the file was left exactly as it was.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The file changed after the [`Version`](crate::Version) given to
    /// [`Options::unchanged_since`](crate::Options::unchanged_since) was taken.
    Conflict { path: PathBuf },
    /// [`Options::create_new`](crate::Options::create_new) was set and the file exists.
    Exists { path: PathBuf },
    /// The path names something other than a regular file, such as a directory.
    NotAFile { path: PathBuf },
    /// The file exists but this process may not write to it.
    ReadOnly { path: PathBuf },
    /// Following the path's symlinks went round more than 40 times.
    SymlinkLoop { path: PathBuf },
    /// The path leads through a symlink, or to a file, in a sticky, world-writable directory such as
    /// `/tmp` that belongs to another user (neither this one nor the directory's owner). Writing
    /// through it would let that user choose what gets overwritten, so the kernel refuses to as
    /// well (`fs.protected_symlinks`, `fs.protected_regular`).
    Untrusted { path: PathBuf },
    /// Overwriting the file in place failed partway, so it may now hold part of the new contents.
    /// The complete new contents are in the file at `staged`, which was kept so they can be
    /// recovered.
    Interrupted {
        path: PathBuf,
        staged: PathBuf,
        source: io::Error,
    },
    /// Replacing the file failed partway and couldn't be undone (Windows only, when `ReplaceFileW`
    /// fails at its last step and the old file can't be moved back). There may be no file at `path`:
    /// the old contents are at `old` and the new ones at `new`.
    Stranded {
        path: PathBuf,
        old: PathBuf,
        new: PathBuf,
        source: io::Error,
    },
    /// Any other I/O failure: what was being done, to which path, and the error.
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

impl Error {
    pub(crate) fn io(action: &'static str, path: impl Into<PathBuf>, source: io::Error) -> Error {
        Error::Io {
            action,
            path: path.into(),
            source,
        }
    }

    /// The path the error is about.
    pub fn path(&self) -> &Path {
        match self {
            Error::Conflict { path }
            | Error::Exists { path }
            | Error::NotAFile { path }
            | Error::ReadOnly { path }
            | Error::SymlinkLoop { path }
            | Error::Untrusted { path }
            | Error::Interrupted { path, .. }
            | Error::Stranded { path, .. }
            | Error::Io { path, .. } => path,
        }
    }

    /// The closest [`io::ErrorKind`].
    pub fn kind(&self) -> io::ErrorKind {
        match self {
            Error::Conflict { .. } | Error::SymlinkLoop { .. } => io::ErrorKind::Other,
            Error::Exists { .. } => io::ErrorKind::AlreadyExists,
            Error::NotAFile { .. } => io::ErrorKind::InvalidInput,
            Error::ReadOnly { .. } | Error::Untrusted { .. } => io::ErrorKind::PermissionDenied,
            Error::Interrupted { source, .. }
            | Error::Stranded { source, .. }
            | Error::Io { source, .. } => source.kind(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Conflict { path } => {
                write!(f, "{} changed on disk since it was read", path.display())
            }
            Error::Exists { path } => write!(f, "{} already exists", path.display()),
            Error::NotAFile { path } => write!(f, "{} is not a regular file", path.display()),
            Error::ReadOnly { path } => write!(f, "{} is read-only", path.display()),
            Error::SymlinkLoop { path } => {
                write!(f, "too many levels of symbolic links at {}", path.display())
            }
            Error::Untrusted { path } => write!(
                f,
                "{} is in a sticky, world-writable directory and belongs to another user, so it isn't followed or written",
                path.display()
            ),
            Error::Stranded {
                path,
                old,
                new,
                source,
            } => write!(
                f,
                "replacing {} failed partway ({source}); the old contents are in {} and the new ones in {}",
                path.display(),
                old.display(),
                new.display()
            ),
            Error::Interrupted {
                path,
                staged,
                source,
            } => write!(
                f,
                "writing {} in place failed partway ({source}); the complete new contents are in {}",
                path.display(),
                staged.display()
            ),
            Error::Io {
                action,
                path,
                source,
            } => write!(f, "could not {action} {}: {source}", path.display()),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Interrupted { source, .. }
            | Error::Stranded { source, .. }
            | Error::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<Error> for io::Error {
    fn from(error: Error) -> io::Error {
        io::Error::new(error.kind(), error)
    }
}
