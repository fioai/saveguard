use std::collections::hash_map::DefaultHasher;
use std::fs::File;
use std::hash::Hasher;
use std::io::{self, Read};
use std::path::Path;

use crate::{sys, Error, Result};

/// A snapshot of a file, for noticing later that it changed.
///
/// Get one from [`read`](crate::read) (which also remembers a hash of the contents), from
/// [`Version::of`] (metadata only), or from the [`Report`](crate::Report) of the last save, and pass
/// it to [`Options::unchanged_since`](crate::Options::unchanged_since).
///
/// With a hash of the contents, a version counts as unchanged exactly when the file still has
/// those contents, so a rewrite with the same bytes isn't a conflict, and a change that leaves the
/// size and modification time the same (possible within one tick of the file system's clock) is.
/// Checking means reading the file again. Without one, any change of size, modification time or
/// identity (another program replacing the file) counts as a change.
///
/// A version is meant for the process that took it: it isn't stable across saveguard releases.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version(pub(crate) State);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    Absent,
    Present {
        stamp: Stamp,
        contents: Option<Contents>,
    },
}

/// The metadata that changes when a file is written or replaced. `dev` and `ino` are the volume
/// and file index on Windows, and `mtime` is in the platform's units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Stamp {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Contents {
    pub len: u64,
    pub hash: u64,
}

impl Version {
    /// The file at `path` as it is now, from its metadata (symlinks are followed). A missing file
    /// gives [`Version::absent`].
    pub fn of(path: impl AsRef<Path>) -> Result<Version> {
        let path = path.as_ref();
        match sys::stamp_at(path) {
            Ok(Some(stamp)) => Ok(Version(State::Present {
                stamp,
                contents: None,
            })),
            Ok(None) => Ok(Version(State::Absent)),
            Err(e) => Err(Error::io("inspect", path, e)),
        }
    }

    /// No file. As an expected version it means the file must still not exist.
    pub fn absent() -> Version {
        Version(State::Absent)
    }

    /// Whether the file existed.
    pub fn exists(&self) -> bool {
        matches!(self.0, State::Present { .. })
    }

    /// The file's size in bytes, if it existed.
    pub fn size(&self) -> Option<u64> {
        match self.0 {
            State::Absent => None,
            State::Present { stamp, .. } => Some(stamp.size),
        }
    }

    /// For the C API: the version as plain numbers.
    #[doc(hidden)]
    pub fn to_raw(&self) -> [u64; 8] {
        match self.0 {
            State::Absent => [1, 0, 0, 0, 0, 0, 0, 0],
            State::Present { stamp, contents } => {
                let (has, len, hash) = contents.map_or((0, 0, 0), |c| (1, c.len, c.hash));
                [
                    2,
                    stamp.dev,
                    stamp.ino,
                    stamp.size,
                    stamp.mtime as u64,
                    has,
                    len,
                    hash,
                ]
            }
        }
    }

    /// For the C API: the inverse of [`Version::to_raw`]. `None` for numbers it didn't make.
    #[doc(hidden)]
    pub fn from_raw(raw: [u64; 8]) -> Option<Version> {
        match raw[0] {
            1 => Some(Version(State::Absent)),
            2 => Some(Version(State::Present {
                stamp: Stamp {
                    dev: raw[1],
                    ino: raw[2],
                    size: raw[3],
                    mtime: raw[4] as i64,
                },
                contents: match raw[5] {
                    0 => None,
                    1 => Some(Contents {
                        len: raw[6],
                        hash: raw[7],
                    }),
                    _ => return None,
                },
            })),
            _ => None,
        }
    }
}

/// Hashes contents as they are written. Feeding the same bytes in different pieces gives the same
/// result.
pub(crate) struct ContentHash {
    hasher: DefaultHasher,
    len: u64,
}

impl ContentHash {
    pub fn new() -> ContentHash {
        ContentHash {
            hasher: DefaultHasher::new(),
            len: 0,
        }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.hasher.write(bytes);
        self.len += bytes.len() as u64;
    }

    pub fn finish(&self) -> Contents {
        Contents {
            len: self.len,
            hash: self.hasher.finish(),
        }
    }
}

fn hash_file(path: &Path) -> io::Result<Contents> {
    let mut options = File::options();
    options.read(true);
    // A FIFO put at the path would make a blocking open wait forever.
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK);
    let mut file = options.open(path)?;
    let mut hash = ContentHash::new();
    let mut buf = vec![0; 64 * 1024];
    loop {
        match file.read(&mut buf) {
            Ok(0) => return Ok(hash.finish()),
            Ok(n) => hash.update(&buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

pub(crate) fn read(path: &Path) -> Result<(Vec<u8>, Version)> {
    let mut file = File::open(path).map_err(|e| Error::io("open", path, e))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| Error::io("read", path, e))?;
    let stamp = sys::stamp_of(&file).map_err(|e| Error::io("inspect", path, e))?;
    let mut hash = ContentHash::new();
    hash.update(&bytes);
    let version = Version(State::Present {
        stamp,
        contents: Some(hash.finish()),
    });
    Ok((bytes, version))
}

/// Whether the file at `path` is still the `expected` version.
pub(crate) fn unchanged(expected: &Version, path: &Path) -> io::Result<bool> {
    let now = sys::stamp_at(path)?;
    Ok(match (&expected.0, now) {
        (State::Absent, None) => true,
        (State::Absent, Some(_)) | (State::Present { .. }, None) => false,
        (
            State::Present {
                stamp,
                contents: None,
            },
            Some(now),
        ) => *stamp == now,
        (
            State::Present {
                contents: Some(contents),
                ..
            },
            Some(now),
        ) => now.size == contents.len && hash_file(path)? == *contents,
    })
}
