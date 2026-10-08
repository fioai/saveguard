use std::fmt;
use std::path::PathBuf;

use crate::Version;

/// How a save was carried out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// There was no file, so a new one was created. Other processes never saw it half written.
    Created,
    /// A complete new file was renamed over the old one, atomically: other processes saw either the
    /// old contents or the new ones, never a mixture.
    Replaced,
    /// The new contents were written into the existing file, which keeps its identity and all its
    /// metadata. Other processes reading during the save could see a mixture.
    Overwrote,
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Method::Created => "created",
            Method::Replaced => "replaced",
            Method::Overwrote => "overwrote in place",
        })
    }
}

/// Why a save overwrote the file in place instead of replacing it atomically.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reason {
    /// [`Strategy::Overwrite`](crate::Strategy::Overwrite) was asked for.
    Requested,
    /// The file has this many names (hard links). A replacement would have only the one, and the
    /// others would keep the old contents.
    HardLinks(u64),
    /// The file is a mount point, as with a Docker bind mount of a single file. A rename can't
    /// replace it (`EBUSY`).
    MountPoint,
    /// A new file can't be created next to it, so there is nothing to rename into place.
    DirectoryNotWritable,
    /// The file belongs to another user, and a new file would belong to this process's user.
    Owner,
    /// The file belongs to a group this process isn't in, and a new file couldn't be given it.
    Group,
    /// Something about the file couldn't be copied to a new one, described here (for example
    /// `"extended attribute security.selinux: Permission denied"`).
    Metadata(String),
    /// The rename that would have replaced the file was refused, with this error.
    RenameFailed(String),
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reason::Requested => f.write_str("overwriting was requested"),
            Reason::HardLinks(n) => write!(f, "the file has {n} hard links"),
            Reason::MountPoint => f.write_str("the file is a mount point"),
            Reason::DirectoryNotWritable => f.write_str("its directory is not writable"),
            Reason::Owner => f.write_str("a new file would not keep its owner"),
            Reason::Group => f.write_str("a new file would not keep its group"),
            Reason::Metadata(what) => write!(f, "could not copy {what}"),
            Reason::RenameFailed(error) => write!(f, "the rename failed: {error}"),
        }
    }
}

/// Something the file had before the save that it doesn't have after.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Lost {
    /// The file had this many hard links and was replaced, so the other names still have the old
    /// contents. Only with [`Strategy::Replace`](crate::Strategy::Replace).
    HardLinks(u64),
    /// The file now belongs to this process's user. Only with
    /// [`Strategy::Replace`](crate::Strategy::Replace).
    Owner,
    /// The file now has this process's group. Only with
    /// [`Strategy::Replace`](crate::Strategy::Replace).
    Group,
    /// The permission bits. Only with [`Strategy::Replace`](crate::Strategy::Replace).
    Permissions,
    /// The setuid bit, or the setgid bit of a group-executable file. They are cleared whenever the
    /// contents change, as the kernel does for a write in place.
    SetId,
    /// Linux file capabilities (`security.capability`), which the kernel clears whenever a file's
    /// contents change.
    Capabilities,
    /// The access control list.
    Acl,
    /// The security label (SELinux, Smack).
    SecurityLabel,
    /// The named extended attribute.
    Xattr(String),
    /// Whatever extended attributes the file had: they couldn't be read (the file wasn't readable,
    /// or listing them failed), so it isn't known whether there were any. Only with
    /// [`Strategy::Replace`](crate::Strategy::Replace).
    UnreadableXattrs,
    /// File flags (`chattr` on Linux, `chflags` on macOS), such as no-dump or no-copy-on-write.
    Flags,
}

impl fmt::Display for Lost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Lost::HardLinks(n) => write!(f, "the other {} hard links", n.saturating_sub(1)),
            Lost::Owner => f.write_str("the owner"),
            Lost::Group => f.write_str("the group"),
            Lost::Permissions => f.write_str("the permissions"),
            Lost::SetId => f.write_str("the setuid/setgid bits"),
            Lost::Capabilities => f.write_str("file capabilities"),
            Lost::Acl => f.write_str("the access control list"),
            Lost::SecurityLabel => f.write_str("the security label"),
            Lost::Xattr(name) => write!(f, "extended attribute {name}"),
            Lost::UnreadableXattrs => {
                f.write_str("any extended attributes (they couldn't be read)")
            }
            Lost::Flags => f.write_str("file flags"),
        }
    }
}

/// What a save did.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Report {
    /// The file that was written: the path that was given, or where its symlinks led.
    pub path: PathBuf,
    /// How the new contents were put in place.
    pub method: Method,
    /// Why the file was overwritten in place rather than replaced. Empty unless `method` is
    /// [`Method::Overwrote`].
    pub reasons: Vec<Reason>,
    /// What the file had before that it doesn't have now. Usually empty.
    pub lost: Vec<Lost>,
    /// The file's version after the save, to pass to
    /// [`Options::unchanged_since`](crate::Options::unchanged_since) next time.
    pub version: Version,
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        describe(
            f,
            Tense::Past,
            self.method,
            &self.path,
            &self.reasons,
            &self.lost,
        )
    }
}

/// How a save would go, from [`Options::plan`](crate::Options::plan).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Plan {
    /// The file that would be written: the path that was given, or where its symlinks lead.
    pub path: PathBuf,
    /// How the new contents would be put in place.
    pub method: Method,
    /// Why the file would be overwritten in place rather than replaced.
    pub reasons: Vec<Reason>,
    /// What the file would lose.
    pub lost: Vec<Lost>,
}

impl fmt::Display for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        describe(
            f,
            Tense::Future,
            self.method,
            &self.path,
            &self.reasons,
            &self.lost,
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tense {
    Past,
    Future,
}

/// "replaced a.txt", "overwrote a.txt in place (the file has 2 hard links)",
/// "would replace a.txt; would lose the setuid/setgid bits".
fn describe(
    f: &mut fmt::Formatter<'_>,
    tense: Tense,
    method: Method,
    path: &std::path::Path,
    reasons: &[Reason],
    lost: &[Lost],
) -> fmt::Result {
    let verb = match (tense, method) {
        (Tense::Past, Method::Created) => "created",
        (Tense::Past, Method::Replaced) => "replaced",
        (Tense::Past, Method::Overwrote) => "overwrote",
        (Tense::Future, Method::Created) => "would create",
        (Tense::Future, Method::Replaced) => "would replace",
        (Tense::Future, Method::Overwrote) => "would overwrite",
    };
    write!(f, "{verb} {}", path.display())?;
    if method == Method::Overwrote {
        f.write_str(" in place")?;
    }
    if !reasons.is_empty() {
        f.write_str(" (")?;
        list(f, reasons)?;
        f.write_str(")")?;
    }
    if !lost.is_empty() {
        f.write_str(match tense {
            Tense::Past => "; lost ",
            Tense::Future => "; would lose ",
        })?;
        list(f, lost)?;
    }
    Ok(())
}

fn list<T: fmt::Display>(f: &mut fmt::Formatter<'_>, items: &[T]) -> fmt::Result {
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            f.write_str(", ")?;
        }
        write!(f, "{item}")?;
    }
    Ok(())
}
