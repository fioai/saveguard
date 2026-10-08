use std::io::Write;
use std::path::Path;

use crate::{writer, Error, Plan, Report, Result, Version, Writer};

/// How to put the new contents in place.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Strategy {
    /// Replace the file atomically when nothing about it would be lost, and otherwise overwrite it
    /// in place. The default.
    #[default]
    Auto,
    /// Always write a new file and rename it over the old one, reporting in
    /// [`Report::lost`](crate::Report::lost) anything the new file couldn't keep.
    Replace,
    /// Always write the new contents into the existing file, which keeps its identity (hard links,
    /// mounts, open handles) and all its metadata, but isn't atomic: readers can see it half
    /// written.
    Overwrite,
}

/// Whether to wait for the save to reach the disk.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Durability {
    /// Flush the new contents, and the directory entry that points at them, to the disk before
    /// returning (`fsync`, and `F_FULLFSYNC` on macOS). The default.
    #[default]
    Full,
    /// Don't flush. Saves are still atomic for other processes, but after a power cut or a kernel
    /// crash soon after, the file can hold the old contents, the new ones, or on some file systems
    /// nothing at all.
    None,
}

/// Options for saving a file, in the style of [`std::fs::OpenOptions`].
///
/// ```no_run
/// use saveguard::{Options, Strategy};
/// # fn main() -> saveguard::Result<()> {
/// Options::new()
///     .strategy(Strategy::Auto)
///     .follow_symlinks(true)
///     .save("config.toml", "answer = 42\n")?;
/// # Ok(()) }
/// ```
#[derive(Clone, Debug, Default)]
pub struct Options {
    pub(crate) strategy: Strategy,
    pub(crate) no_follow: bool,
    pub(crate) durability: Durability,
    pub(crate) mode: Option<u32>,
    pub(crate) expect: Option<Version>,
    pub(crate) create_new: bool,
}

impl Options {
    /// The defaults: [`Strategy::Auto`], symlinks followed, [`Durability::Full`].
    pub fn new() -> Options {
        Options::default()
    }

    /// How to put the new contents in place. See [`Strategy`].
    pub fn strategy(&mut self, strategy: Strategy) -> &mut Options {
        self.strategy = strategy;
        self
    }

    /// Whether a symlink is followed to the file it points to (the default), through any number of
    /// links, so that the file is saved and the links stay links. With `false`, a symlink at the
    /// path is itself replaced by a regular file holding the new contents.
    pub fn follow_symlinks(&mut self, follow: bool) -> &mut Options {
        self.no_follow = !follow;
        self
    }

    /// Whether to wait for the save to reach the disk. See [`Durability`].
    pub fn durability(&mut self, durability: Durability) -> &mut Options {
        self.durability = durability;
        self
    }

    /// The permissions for a file that doesn't exist yet, before the umask is applied, as with
    /// `open(2)`. The default is `0o666`. An existing file always keeps its own permissions.
    /// Has no effect on Windows.
    pub fn mode(&mut self, mode: u32) -> &mut Options {
        self.mode = Some(mode);
        self
    }

    /// Fail with [`Error::Conflict`] if the file is no longer the given version: if anything has
    /// written it, replaced it, deleted it or (for [`Version::absent`]) created it since. Nothing is
    /// written when that happens.
    ///
    /// The check is made once before anything is written and again just before the new contents
    /// are put in place; for an overwrite in place, while holding a lock that other saveguard saves
    /// of the file wait for. A replacement can still race another process between that check and
    /// its rename.
    pub fn unchanged_since(&mut self, version: &Version) -> &mut Options {
        self.expect = Some(version.clone());
        self
    }

    /// Fail with [`Error::Exists`] if the file already exists, including if another process creates
    /// it while this save is being written, and if the path is a symlink (even one to a file that
    /// doesn't exist), as with `O_EXCL`. Where the file system allows it, the file is created
    /// atomically: it never appears half written and is never replaced.
    pub fn create_new(&mut self, create_new: bool) -> &mut Options {
        self.create_new = create_new;
        self
    }

    /// Saves `contents` to the file at `path`. See [`save`](crate::save).
    pub fn save(&self, path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> Result<Report> {
        let mut writer = self.open(path)?;
        if let Err(e) = writer.write_all(contents.as_ref()) {
            let staged = writer.staged_path().to_path_buf();
            return Err(Error::io("write the new contents to", staged, e));
        }
        writer.commit()
    }

    /// Starts a save that is written piece by piece. The contents go to a new file next to the
    /// target, and nothing happens to the target itself until [`Writer::commit`]. Dropping the
    /// writer without committing deletes that file.
    pub fn open(&self, path: impl AsRef<Path>) -> Result<Writer> {
        writer::open(self, path.as_ref())
    }

    /// Says how a save of `path` would go, without writing anything. A real save can still turn
    /// out differently: it finds out at the last moment whether, say, an extended attribute can be
    /// copied, and the file can change in between.
    pub fn plan(&self, path: impl AsRef<Path>) -> Result<Plan> {
        writer::plan(self, path.as_ref())
    }
}
