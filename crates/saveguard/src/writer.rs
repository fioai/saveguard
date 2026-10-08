use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::options::{Durability, Options, Strategy};
use crate::resolve::{resolve, Target};
use crate::sys::{self, Facts, Failure, Put, ReplaceError};
use crate::version::{self, ContentHash, Stamp, State};
use crate::{Error, Lost, Method, Plan, Reason, Report, Result, Version};

/// A save in progress, from [`Options::open`].
///
/// Write the new contents to it, then call [`commit`](Writer::commit). Until then the target file
/// is untouched; dropping the writer without committing deletes what was written.
pub struct Writer {
    pending: Option<Pending>,
}

struct Pending {
    target: Target,
    original: Option<sys::Original>,
    decision: Decision,
    failures: Vec<Failure>,
    out: BufWriter<File>,
    staged: PathBuf,
    hash: ContentHash,
    strategy: Strategy,
    durability: Durability,
    expect: Option<Version>,
    create_new: bool,
}

/// What exists at the target when the save starts.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Existing {
    Nothing,
    /// A symlink that isn't being followed: it gets replaced by a regular file.
    Link,
    File(Facts),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Decision {
    pub method: Method,
    pub reasons: Vec<Reason>,
    pub lost: Vec<Lost>,
}

/// The policy: replace atomically unless that would lose something, and say what is lost either
/// way. This only uses what can be known before writing; [`Pending::commit`] switches to
/// overwriting if copying the metadata or the rename then fails.
pub(crate) fn decide(strategy: Strategy, existing: Existing) -> Decision {
    let facts = match existing {
        Existing::Nothing => return decision(Method::Created, vec![], vec![]),
        Existing::Link => return decision(Method::Replaced, vec![], vec![]),
        Existing::File(facts) => facts,
    };
    // Lost however the contents change, because the kernel clears them on a write in place too.
    let mut lost = Vec::new();
    if facts.setid {
        lost.push(Lost::SetId);
    }
    if facts.capabilities {
        lost.push(Lost::Capabilities);
    }
    match strategy {
        Strategy::Overwrite => decision(Method::Overwrote, vec![Reason::Requested], lost),
        Strategy::Replace => {
            if facts.links > 1 {
                lost.push(Lost::HardLinks(facts.links));
            }
            if !facts.owner_kept {
                lost.push(Lost::Owner);
            }
            if !facts.group_kept {
                lost.push(Lost::Group);
            }
            decision(Method::Replaced, vec![], lost)
        }
        Strategy::Auto => {
            let mut reasons = Vec::new();
            if facts.links > 1 {
                reasons.push(Reason::HardLinks(facts.links));
            }
            if facts.mount_point {
                reasons.push(Reason::MountPoint);
            }
            if !facts.owner_kept {
                reasons.push(Reason::Owner);
            } else if !facts.group_kept {
                reasons.push(Reason::Group);
            }
            let method = if reasons.is_empty() {
                Method::Replaced
            } else {
                Method::Overwrote
            };
            decision(method, reasons, lost)
        }
    }
}

fn decision(method: Method, reasons: Vec<Reason>, lost: Vec<Lost>) -> Decision {
    Decision {
        method,
        reasons,
        lost,
    }
}

/// Adds what was lost, once.
fn add_lost(lost: &mut Vec<Lost>, more: impl IntoIterator<Item = Lost>) {
    for item in more {
        if !lost.contains(&item) {
            lost.push(item);
        }
    }
}

fn existing(original: Option<&sys::Original>) -> Existing {
    match original {
        None => Existing::Nothing,
        Some(o) if o.is_file() => Existing::File(o.facts()),
        Some(_) => Existing::Link,
    }
}

/// Like `O_EXCL`, `create_new` treats a symlink at the path as the file existing, even one that
/// points nowhere: otherwise whoever made the link would choose where the new file goes.
fn refuse_link(opts: &Options, path: &Path) -> Result<()> {
    if opts.create_new && fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
    {
        return Err(Error::Exists { path: path.into() });
    }
    Ok(())
}

/// Checks that apply before anything is written, to `open` and `plan` alike.
fn check(opts: &Options, target: &Target, original: Option<&sys::Original>) -> Result<()> {
    if let Some(o) = original {
        if !o.is_file() && !o.is_symlink() {
            return Err(Error::NotAFile {
                path: target.file.clone(),
            });
        }
        if opts.create_new {
            return Err(Error::Exists {
                path: target.file.clone(),
            });
        }
        if o.is_file() && !o.trusted(&target.file) {
            return Err(Error::Untrusted {
                path: target.file.clone(),
            });
        }
        if o.is_file()
            && !sys::writable(&target.file).map_err(|e| Error::io("inspect", &target.file, e))?
        {
            return Err(Error::ReadOnly {
                path: target.file.clone(),
            });
        }
    }
    check_unchanged(opts.expect.as_ref(), &target.file)
}

fn check_unchanged(expect: Option<&Version>, path: &Path) -> Result<()> {
    if let Some(expected) = expect {
        if !version::unchanged(expected, path).map_err(|e| Error::io("inspect", path, e))? {
            return Err(Error::Conflict { path: path.into() });
        }
    }
    Ok(())
}

fn inspect(target: &Target) -> Result<Option<sys::Original>> {
    sys::inspect(&target.file).map_err(|e| Error::io("inspect", &target.file, e))
}

pub(crate) fn plan(opts: &Options, path: &Path) -> Result<Plan> {
    refuse_link(opts, path)?;
    let target = resolve(path, !opts.no_follow)?;
    let original = inspect(&target)?;
    check(opts, &target, original.as_ref())?;
    let existing = existing(original.as_ref());
    let mut d = decide(opts.strategy, existing);
    if d.method == Method::Replaced
        && opts.strategy == Strategy::Auto
        && matches!(existing, Existing::File(_))
        && !sys::dir_writable(&target.dir)
    {
        d.method = Method::Overwrote;
        d.reasons.push(Reason::DirectoryNotWritable);
    }
    Ok(Plan {
        path: target.file,
        method: d.method,
        reasons: d.reasons,
        lost: d.lost,
    })
}

pub(crate) fn open(opts: &Options, path: &Path) -> Result<Writer> {
    refuse_link(opts, path)?;
    let target = resolve(path, !opts.no_follow)?;
    let original = inspect(&target)?;
    check(opts, &target, original.as_ref())?;
    let existing = existing(original.as_ref());
    let mut decision = decide(opts.strategy, existing);
    let staged = stage(opts, &target, &mut decision, existing)?;
    let mut failures = Vec::new();
    if decision.method == Method::Replaced {
        if let Some(o) = original.as_ref().filter(|o| o.is_file()) {
            // Some file flags can only be set while the file is empty.
            sys::prepare(&staged.file, o, &mut failures);
        }
    }
    Ok(Writer {
        pending: Some(Pending {
            target,
            original,
            decision,
            failures,
            out: BufWriter::with_capacity(64 * 1024, staged.file),
            staged: staged.path,
            hash: ContentHash::new(),
            strategy: opts.strategy,
            durability: opts.durability,
            expect: opts.expect.clone(),
            create_new: opts.create_new,
        }),
    })
}

/// Creates the file the new contents are written to: next to the target, so that it can be renamed
/// over it, or, when that directory is closed to us and the target can be overwritten instead,
/// somewhere that survives a reboot.
fn stage(
    opts: &Options,
    target: &Target,
    decision: &mut Decision,
    existing: Existing,
) -> Result<sys::Staged> {
    let name = target.file.file_name();
    // A file that replaces another starts private and gets the original's permissions at the end,
    // so a secret file is never briefly readable by others. A file where there was none (or only a
    // link) gets its mode, and the umask or the directory's default ACL, at creation, like any
    // other.
    let mode = match existing {
        Existing::Nothing | Existing::Link => Some(opts.mode.unwrap_or(0o666)),
        Existing::File(_) => None,
    };
    match sys::create_staged(&target.dir, name, mode) {
        Ok(staged) => Ok(staged),
        Err(e)
            if matches!(existing, Existing::File(_))
                && opts.strategy != Strategy::Replace
                && sys::is_denied(&e) =>
        {
            if decision.method == Method::Replaced {
                decision.method = Method::Overwrote;
                decision.reasons.push(Reason::DirectoryNotWritable);
            }
            let dir = sys::fallback_dir();
            sys::create_staged(&dir, name, None)
                .map_err(|e| Error::io("create a temporary file in", dir, e))
        }
        Err(e) => Err(Error::io("create a temporary file in", &target.dir, e)),
    }
}

impl Writer {
    /// The file this save will write: the path given, or where its symlinks lead.
    pub fn path(&self) -> &Path {
        &self.pending().target.file
    }

    /// How the new contents are going to be put in place, as far as is known before committing.
    pub fn method(&self) -> Method {
        self.pending().decision.method
    }

    /// Puts the new contents in place and says how that went. On an error the target is unchanged,
    /// except after [`Error::Interrupted`] and [`Error::Stranded`].
    pub fn commit(mut self) -> Result<Report> {
        let pending = self
            .pending
            .take()
            .expect("a Writer is committed at most once");
        pending.commit()
    }

    /// Abandons the save: the target is left alone and what was written is deleted. The same as
    /// dropping the writer, except that it says whether the deletion worked.
    pub fn abort(mut self) -> io::Result<()> {
        let pending = self
            .pending
            .take()
            .expect("a Writer is aborted at most once");
        let Pending { out, staged, .. } = pending;
        drop(out.into_parts());
        fs::remove_file(staged)
    }

    pub(crate) fn staged_path(&self) -> &Path {
        &self.pending().staged
    }

    fn pending(&self) -> &Pending {
        self.pending.as_ref().expect("the Writer is still open")
    }
}

impl Write for Writer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let pending = self.pending.as_mut().expect("the Writer is still open");
        let n = pending.out.write(buf)?;
        pending.hash.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.pending
            .as_mut()
            .expect("the Writer is still open")
            .out
            .flush()
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        if let Some(pending) = self.pending.take() {
            let Pending { out, staged, .. } = pending;
            // Close the file before deleting it (Windows wants that); the buffer is thrown away.
            drop(out.into_parts());
            let _ = fs::remove_file(staged);
        }
    }
}

/// Deletes the staged file when a commit ends, unless disarmed because it holds contents that
/// would otherwise be lost. After a successful replace it no longer exists, and this does nothing.
struct Cleanup(Option<PathBuf>);

impl Cleanup {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = fs::remove_file(path);
        }
    }
}

impl Pending {
    fn commit(self) -> Result<Report> {
        let Pending {
            target,
            original,
            decision,
            failures,
            out,
            staged,
            hash,
            strategy,
            durability,
            expect,
            create_new,
        } = self;
        let Decision {
            mut method,
            mut reasons,
            mut lost,
        } = decision;
        let mut failures = failures;
        let mut cleanup = Cleanup(Some(staged.clone()));
        let mut file = out
            .into_inner()
            .map_err(|e| Error::io("write the new contents to", &staged, e.into_error()))?;
        let contents = hash.finish();
        let sync = durability == Durability::Full;
        let original_file = original.as_ref().filter(|o| o.is_file());

        // Give the new file everything the old one had. If something won't copy, Auto overwrites
        // the old file instead, which keeps it all.
        if method == Method::Replaced {
            if let Some(o) = original_file {
                sys::copy_metadata(&file, o, &mut failures);
            }
            if !failures.is_empty() {
                if strategy == Strategy::Auto {
                    method = Method::Overwrote;
                    reasons.extend(failures.iter().map(|f| Reason::Metadata(f.detail.clone())));
                } else {
                    add_lost(&mut lost, failures.iter().map(|f| f.lost.clone()));
                }
            }
        }

        // The staged file is about to become the file, or is the copy that an overwrite in place
        // can be recovered from, so it goes to disk first either way.
        if sync {
            file.sync_all()
                .map_err(|e| Error::io("flush the new contents to", &staged, e))?;
        }

        let in_place = Overwrite {
            staged: &staged,
            target: &target.file,
            len: contents.len,
            sync,
            expect: expect.as_ref(),
        };
        let stamp = match (method, original_file) {
            (Method::Overwrote, Some(o)) => in_place.run(&mut file, o, &mut cleanup)?,
            _ => {
                check_unchanged(expect.as_ref(), &target.file)?;
                let exclusive = create_new || expect.as_ref().is_some_and(|v| !v.exists());
                let put = match (method, original_file.is_some()) {
                    (Method::Created, _) if exclusive => Put::NewExclusive,
                    (Method::Created, _) => Put::New,
                    (_, true) => Put::OverFile,
                    (_, false) => Put::OverLink,
                };
                match sys::replace(file, &staged, &target.file, put, sync) {
                    Ok(stamp) => stamp,
                    Err(ReplaceError {
                        error,
                        stranded: Some(old),
                        ..
                    }) => {
                        cleanup.disarm();
                        return Err(Error::Stranded {
                            path: target.file,
                            old,
                            new: staged,
                            source: error,
                        });
                    }
                    Err(ReplaceError { error, .. })
                        if put == Put::NewExclusive
                            && error.kind() == io::ErrorKind::AlreadyExists =>
                    {
                        let path = target.file;
                        return Err(if create_new {
                            Error::Exists { path }
                        } else {
                            Error::Conflict { path }
                        });
                    }
                    Err(ReplaceError { error, file, .. })
                        if put == Put::OverFile
                            && strategy == Strategy::Auto
                            && sys::rename_refused(&error) =>
                    {
                        method = Method::Overwrote;
                        reasons.push(Reason::RenameFailed(error.to_string()));
                        let mut file = match file {
                            Some(file) => file,
                            None => {
                                File::open(&staged).map_err(|e| Error::io("reopen", &staged, e))?
                            }
                        };
                        let o = original_file.expect("an OverFile replace has an original");
                        in_place.run(&mut file, o, &mut cleanup)?
                    }
                    Err(ReplaceError { error, .. }) => {
                        return Err(Error::io("replace", &target.file, error))
                    }
                }
            }
        };

        if method != Method::Overwrote {
            reasons.clear();
        }
        Ok(Report {
            path: target.file,
            method,
            reasons,
            lost,
            version: Version(State::Present {
                stamp,
                contents: Some(contents),
            }),
        })
    }
}

/// Overwriting the target in place from the staged file.
struct Overwrite<'a> {
    staged: &'a Path,
    target: &'a Path,
    len: u64,
    sync: bool,
    expect: Option<&'a Version>,
}

impl Overwrite<'_> {
    /// Opens and locks the target, makes sure it's still the file that was inspected and (with
    /// `unchanged_since`) still the expected version, then copies the staged contents over it.
    /// The staged file is closed by the caller, at the end of its match arm, before `cleanup`
    /// deletes it.
    fn run(
        &self,
        file: &mut File,
        original: &sys::Original,
        cleanup: &mut Cleanup,
    ) -> Result<Stamp> {
        let mut to = match sys::open_existing(self.target, original) {
            Ok(Some(to)) => to,
            Ok(None) => {
                return Err(Error::Conflict {
                    path: self.target.into(),
                })
            }
            Err(e) => return Err(Error::io("open", self.target, e)),
        };
        // Checked while holding the lock, so another save of the file can't come in between.
        check_unchanged(self.expect, self.target)?;
        match sys::overwrite(file, &mut to, self.len, self.sync) {
            Ok(stamp) => Ok(stamp),
            Err(sys::OverwriteError {
                touched: false,
                error,
            }) => Err(Error::io("write", self.target, error)),
            Err(sys::OverwriteError {
                touched: true,
                error,
            }) => {
                cleanup.disarm();
                Err(Error::Interrupted {
                    path: self.target.into(),
                    staged: self.staged.into(),
                    source: error,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> Facts {
        Facts {
            links: 1,
            mount_point: false,
            owner_kept: true,
            group_kept: true,
            setid: false,
            capabilities: false,
        }
    }

    #[test]
    fn a_plain_file_is_replaced() {
        let d = decide(Strategy::Auto, Existing::File(facts()));
        assert_eq!(d, decision(Method::Replaced, vec![], vec![]));
    }

    #[test]
    fn nothing_there_is_created_whatever_the_strategy() {
        for s in [Strategy::Auto, Strategy::Replace, Strategy::Overwrite] {
            assert_eq!(decide(s, Existing::Nothing).method, Method::Created);
        }
    }

    #[test]
    fn an_unfollowed_link_is_replaced_whatever_the_strategy() {
        for s in [Strategy::Auto, Strategy::Replace, Strategy::Overwrite] {
            assert_eq!(decide(s, Existing::Link).method, Method::Replaced);
        }
    }

    #[test]
    fn auto_overwrites_whatever_a_replacement_would_lose() {
        let cases = [
            (
                Facts {
                    links: 3,
                    ..facts()
                },
                Reason::HardLinks(3),
            ),
            (
                Facts {
                    mount_point: true,
                    ..facts()
                },
                Reason::MountPoint,
            ),
            (
                Facts {
                    owner_kept: false,
                    ..facts()
                },
                Reason::Owner,
            ),
            (
                Facts {
                    group_kept: false,
                    ..facts()
                },
                Reason::Group,
            ),
        ];
        for (f, reason) in cases {
            let d = decide(Strategy::Auto, Existing::File(f));
            assert_eq!(d.method, Method::Overwrote, "{reason}");
            assert_eq!(d.reasons, vec![reason]);
            assert!(d.lost.is_empty());
        }
    }

    #[test]
    fn an_unkeepable_owner_is_the_reason_rather_than_the_group_too() {
        let f = Facts {
            owner_kept: false,
            group_kept: false,
            ..facts()
        };
        assert_eq!(
            decide(Strategy::Auto, Existing::File(f)).reasons,
            vec![Reason::Owner]
        );
    }

    #[test]
    fn replace_reports_instead_of_avoiding() {
        let f = Facts {
            links: 2,
            owner_kept: false,
            group_kept: false,
            mount_point: true,
            ..facts()
        };
        let d = decide(Strategy::Replace, Existing::File(f));
        assert_eq!(d.method, Method::Replaced);
        assert!(d.reasons.is_empty());
        assert_eq!(d.lost, vec![Lost::HardLinks(2), Lost::Owner, Lost::Group]);
    }

    #[test]
    fn setid_and_capabilities_are_lost_whatever_the_method() {
        let f = Facts {
            setid: true,
            capabilities: true,
            ..facts()
        };
        for s in [Strategy::Auto, Strategy::Replace, Strategy::Overwrite] {
            assert_eq!(
                decide(s, Existing::File(f)).lost,
                vec![Lost::SetId, Lost::Capabilities]
            );
        }
    }

    #[test]
    fn what_was_lost_is_listed_once() {
        let mut lost = vec![Lost::Owner, Lost::Group];
        add_lost(&mut lost, [Lost::Owner, Lost::Acl, Lost::Group, Lost::Acl]);
        assert_eq!(lost, vec![Lost::Owner, Lost::Group, Lost::Acl]);
    }
}
