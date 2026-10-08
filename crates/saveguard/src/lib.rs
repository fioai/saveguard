//! Save files without wrecking them.
//!
//! Replacing a file's contents looks like a one-liner, but there are only two ways to do it and
//! each one breaks something:
//!
//! - **Overwrite in place.** A crash or a full disk halfway through leaves a truncated file.
//! - **Write a temporary file and rename it over the original.** Crash-safe, but the result is a
//!   new file: hard links stop sharing it, a symlink becomes a plain file, the owner, ACLs,
//!   extended attributes and security label can be lost, and on a Docker bind mount the rename
//!   fails outright.
//!
//! saveguard chooses per file. It replaces atomically when nothing would be lost, and otherwise
//! overwrites in place from a complete copy of the new contents written first, so a crash can't
//! lose them. Every save returns a [`Report`] saying which it did, why, and anything that could not
//! be carried over.
//!
//! ```no_run
//! # fn main() -> saveguard::Result<()> {
//! let report = saveguard::save("settings.json", b"{}\n")?;
//! println!("{report}"); // e.g. "replaced settings.json"
//! # Ok(()) }
//! ```
//!
//! A program that keeps a file open for a while, like an editor, should read it with [`read`] and
//! hand the [`Version`] back with [`Options::unchanged_since`], so that saving fails with
//! [`Error::Conflict`] instead of silently discarding a change someone else made in between:
//!
//! ```no_run
//! # fn main() -> saveguard::Result<()> {
//! let (text, version) = saveguard::read("notes.txt")?;
//! // ... the user edits `text` ...
//! saveguard::Options::new().unchanged_since(&version).save("notes.txt", &text)?;
//! # Ok(()) }
//! ```
//!
//! What is done where, and why, is written up in `docs/design.md` in the repository.

mod error;
mod options;
mod report;
mod resolve;
mod sys;
mod version;
mod writer;

use std::path::Path;

pub use error::{Error, Result};
pub use options::{Durability, Options, Strategy};
pub use report::{Lost, Method, Plan, Reason, Report};
pub use version::Version;
pub use writer::Writer;

/// Replaces the contents of the file at `path` with `contents`, keeping everything else about the
/// file, with the default [`Options`]. Creates the file if it doesn't exist.
///
/// Symlinks are followed: the file they point to is saved and the links stay links.
pub fn save(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> Result<Report> {
    Options::new().save(path, contents)
}

/// Reads the whole file at `path`, along with the [`Version`] that was read, for
/// [`Options::unchanged_since`].
///
/// The version remembers a hash of the contents, so a later check notices a change even when the
/// file's size and modification time came out the same.
pub fn read(path: impl AsRef<Path>) -> Result<(Vec<u8>, Version)> {
    version::read(path.as_ref())
}
