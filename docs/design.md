# How saveguard saves a file, and why

This is the knowledge the library encodes: each way a save goes wrong, how it's detected, and what's done about it. The code points back here.

## The decision

There are two ways to replace a file's contents:

- **Replace:** write a new file next to the old one, then rename it over it. The rename is atomic, so readers see the old contents or the new, never a mixture. A crash leaves one or the other. But the result is a different file (a different inode), so everything attached to the old file rather than to its contents is lost unless it's copied, and some of it can't be copied.
- **Overwrite in place:** write the new contents into the existing file. It's the same file afterwards, so it keeps everything: hard links, mounts, open handles, the owner, ACLs, attributes. But it isn't atomic. Readers can see a mixture, and a crash halfway leaves one.

`Strategy::Auto` replaces unless that would lose something. When it would, it overwrites, but from a complete, flushed copy of the new contents written first (the *staged* file). That copy is next to the target, or in `/var/tmp` when the target's directory won't take it. A crash can then lose the old contents but never the new ones, and a full disk is found before anything is touched (on Linux).

What Auto knows before writing (`writer::decide`, a pure function with unit tests):

| Fact | Reason | How it's found |
|---|---|---|
| more than one hard link | `HardLinks(n)` | `st_nlink`; `nNumberOfLinks` on Windows |
| the file is a mount point | `MountPoint` | `statx` `STATX_ATTR_MOUNT_ROOT` (Linux 5.8+), else a different `st_dev` from the directory's |
| owned by another user, and we're not root | `Owner` | `st_uid` vs `geteuid()` |
| its group is one we're not in, and we're not root | `Group` | `st_gid` vs `getegid()` and `getgroups()` |

macOS's `getgroups` stops at 16 groups. When the answer isn't there, Auto assumes the group can be kept and lets the copy find out.

A bind mount from the same file system has the same device number as the directory it's in. That was checked here: `mount --bind` in a user namespace. So `st_dev` alone doesn't find the case that matters most, the Docker one.

What it finds out while saving, which switches a planned replace to an overwrite:

| Event | Reason |
|---|---|
| the staged file can't be created in the target's directory (`EACCES`, `EPERM`, `EROFS`) | `DirectoryNotWritable` (the staged file goes in `/var/tmp`, which survives a reboot, rather than `/tmp`, which is often in memory) |
| an xattr, the ACL, the security label, the owner, the group, the permissions or the flags won't copy onto the staged file | `Metadata("…")` |
| the rename is refused (`EBUSY`, `EXDEV`, `EPERM`, `EACCES`, `EROFS`, `EINVAL`, `ENOTSUP`; on Windows anything but not-found) | `RenameFailed("…")` |

With `Strategy::Replace` none of that switches anything. The save replaces, or fails if the rename does, and whatever was lost is listed in `Report::lost`. That includes `Lost::UnreadableXattrs` when the xattrs couldn't even be read. `Strategy::Overwrite` always overwrites.

## The steps

1. **Follow the symlinks** (`resolve.rs`) through every hop, up to 40, to the file at the end, which may not exist yet.
   - A writer that follows one hop puts its temporary file next to the middle link. In a Nix store that fails with `EROFS`; elsewhere the rename replaces the middle link with a plain file. That's [anthropics/claude-code#78162](https://github.com/anthropics/claude-code/issues/78162).
   - With `follow_symlinks(false)`, a link at the path is itself replaced.
   - With `create_new`, a link at the path counts as the file existing, even a dangling one, as with `O_EXCL`. Otherwise whoever made the link would choose where the file goes.
   - **Following links by hand skips the kernel's protection for shared directories** (`fs.protected_symlinks`). In a sticky, world-writable directory like `/tmp`, another user can leave a link to one of your files and wait for you to save through it. So each hop gets the kernel's rule (`sys::trusted`): in such a directory, a link is followed only if it belongs to this user or to the directory's owner. Otherwise the save fails with `Error::Untrusted`. The CLI test sets the attack up with two users in a user namespace. With the check removed, the victim's file gets overwritten.
2. **Look at what's there** (`sys::inspect`). `lstat`, then open the file read-only with `O_NOFOLLOW|O_NONBLOCK` to read its xattrs and flags from; a FIFO swapped in would otherwise block the open forever. If it can't be opened (a write-only file), its xattrs can't be read, so a replace might lose them, and Auto overwrites.
3. **Refuse what can't be saved:**
   - not a regular file (`NotAFile`);
   - exists with `create_new` (`Exists`);
   - a file another user left in a shared directory (`Untrusted`, the kernel's `fs.protected_regular` rule);
   - not writable by our *effective* IDs (`ReadOnly`, via `faccessat(…, AT_EACCESS)`). This matters because a rename would succeed on a read-only file the user owns, as long as the directory is writable, and a save shouldn't silently get around a file's permissions.

   Then check `unchanged_since` (`Conflict`).
4. **Create the staged file**, named `.saveguard-<the target's name>-<16 hex digits>.tmp`, so a copy left by a crash can be recognised. It's created with `O_CREAT|O_EXCL`, in the target's directory, so the rename stays on one file system.
   - If it's replacing a file, it's created `0600` (on Windows, with an owner-only DACL) and given the original's permissions at the end. That way the new contents of a private file are never readable by others while they're written.
   - A new file, or one replacing a symlink, is created with the requested mode (`0666` by default), so the umask or the directory's default ACL applies as for any new file.
5. **Copy what must be set while the file is empty:** Linux `chattr` flags. No-copy-on-write (btrfs `+C`) only takes on an empty file.
6. **Write the contents**, hashing them for the report's version.
7. **Copy the metadata** (`sys::copy_metadata`), for a replace:
   - extended attributes, which on Linux include the ACL (`system.posix_acl_access`) and the SELinux or Smack label (`security.*`). One the staged file already has with the same value is left alone, since setting a label can need permission even when nothing changes.
   - then *remove* any the staged file got that the original doesn't have, such as an ACL inherited from the directory's default ACL. Not `security.*` on Linux, nor `com.apple.*` on macOS: those are the system's to set.
   - the ACL on macOS (`fcopyfile(COPYFILE_ACL)`), which isn't an xattr there;
   - owner and group (`fchown`; the group alone if the owner can't be changed);
   - permissions (`fchmod`), after the owner, since changing the owner clears setuid and setgid;
   - `chattr` flags (Linux): secure-delete, undelete, compress, no-compress, sync, no-dump, no-atime, data journaling, no-copy-on-write. Not the ones the file system manages itself, nor immutable or append-only, which stop any save.
   - `chflags` flags (hidden, no-dump) and the creation date on macOS.

   Not copied:
   - `security.capability`: the kernel removes file capabilities whenever a file's contents change, which was checked with `setcap` in a user namespace followed by a write. A replacement does the same and reports `Lost::Capabilities`.
   - `security.ima` and `security.evm`: hashes of the old file, which the kernel maintains.
   - On macOS, whatever `xattr_preserve_for_intent(name, XATTR_OPERATION_INTENT_SAVE)` says not to keep. These are the system's own rules for a safe save, such as attributes that describe the old contents. They're dropped as macOS itself would, not reported.
   - The setuid and setgid bits, where the kernel would clear them. Linux's rule (`setattr_should_drop_suidgid` in `fs/attr.c`) applies when the writer lacks `CAP_FSETID` in the *initial* user namespace:
     - setuid is cleared;
     - setgid is cleared if the file is group-executable, or if the writer isn't in the file's group.

     A replacement follows the same rule, checking the capability (`CapEff` in `/proc/self/status`) and the namespace (`/proc/self/ns/user`), so both methods give the same result and `Lost::SetId` is reported either way. Elsewhere, root keeps the bits.

     One trap: as root in a user namespace, the kernel *does* clear them, because that root lacks the capability in the initial namespace. A first version of this library drew the wrong conclusion from that experiment; the source is the authority.
8. **Flush the staged file** (`fsync`; `F_FULLFSYNC` on macOS, which is what Rust's `sync_all` does there). It's either about to become the file or it's the copy an overwrite can be recovered from.
9. **Put it in place.**
   - **A replace** checks `unchanged_since` again, then calls `rename(2)`, then flushes the directory so the rename survives a crash. Some file systems can't flush a directory; by then the save has happened, so that error is ignored. A small window remains between the check and the rename.
   - **Creating with `create_new`**, or `unchanged_since(&Version::absent())`, uses `renameat2(RENAME_NOREPLACE)` (Linux) or `renamex_np(RENAME_EXCL)` (macOS), so a file that appeared meanwhile is never replaced. Where those aren't supported it falls back to `link` + `unlink`, and on a file system without hard links to a check followed by a rename, which leaves a window.
   - **An overwrite** opens the target `O_WRONLY|O_NOFOLLOW|O_NONBLOCK` (not `O_TRUNC`) and proceeds as follows:
     1. It checks it's the file that was inspected, by `(st_dev, st_ino)`. Only the last path component is protected by `O_NOFOLLOW`, so a directory on the path could have become a symlink in between. Anything else is an `Error::Conflict`.
     2. It takes an exclusive `flock`, so two saveguard saves overwriting one file take turns instead of interleaving their writes. A test runs two at once; without the lock the file comes out a mixture.
     3. Holding the lock, it checks `unchanged_since`.
     4. If the file grows, it reserves the space: `fallocate(FALLOC_FL_KEEP_SIZE)` on Linux, where `ENOSPC` or `EDQUOT` fails the save before the file is touched.
     5. It copies the staged contents over the old ones, truncates to the new length, and flushes.

     If it fails after touching the file, the staged file is kept and `Error::Interrupted` says where it is. Otherwise the staged file is deleted.

The tests were checked by breaking each fix on purpose, and each test then failed: the space reservation (the full-disk test dies partway with `Interrupted`), the lock, the identity check, and the shared-directory rule.

## Windows

`ReplaceFileW` gives the new file the old one's attributes, ACLs, alternate data streams, object ID and creation time, so there's no metadata to copy. It fails rather than lose them, because no `IGNORE_*_ERRORS` flags are passed. It's called with a backup name, so the old file is moved aside rather than deleted, because of what its documentation says about two of its errors:

- `ERROR_UNABLE_TO_MOVE_REPLACEMENT` (1176): with a backup name nothing has changed, so Auto overwrites instead. Without one, the old file is already gone.
- `ERROR_UNABLE_TO_MOVE_REPLACEMENT_2` (1177): the old file is at the backup name and the new one is still staged. The staged file is moved into place, or if that fails, the backup is moved back. If both fail, the save stops with `Error::Stranded`, which names both files. Nothing more is tried, and nothing is deleted.

Sharing violations, lock violations, access denied and 1175 (`UNABLE_TO_REMOVE_REPLACED`) are retried with backoff for about half a second. Virus scanners, indexers and sync clients open files briefly. After that, Auto overwrites in place, which only needs write sharing. Deleting the backup afterwards is retried the same way.

Other details:

- **The staged file** for a replace is created with `CreateFileW` and the DACL `D:P(A;;FA;;;OW)`: protected, so nothing is inherited from the directory, with all access for the owner. `ReplaceFileW` gives it the original's DACL at the end.
- **Durability:** `ReplaceFileW` has no write-through option (its `REPLACEFILE_WRITE_THROUGH` is documented as unsupported), so with `Durability::Full` the file is flushed after the replace, as the best available.
- **Overwrites in place** lock one byte far past the end of the file with `LockFileEx`. Windows locks are mandatory, and locking the contents would make other programs' reads fail rather than wait.
- **New files, replaced symlinks and exclusive creation** use `MoveFileExW`, with `MOVEFILE_WRITE_THROUGH` unless `Durability::None` and `MOVEFILE_REPLACE_EXISTING` unless exclusive.
- **Read-only:** the read-only attribute counts as read-only.
- **Identity:** `GetFileInformationByHandle` supplies the hard-link count, the identity check (volume serial and file index), and the version (those plus size and last-write time).

## Versions and conflicts

A `Version` is the file's `(dev, ino, size, mtime)`, and from `read()` or a save's report also the length and a hash of its contents.

- With contents, the check is whether the file still has those contents: the same size, then the same hash, which means reading it again. Rewriting the same bytes isn't a conflict. A change that leaves the size and mtime the same is. That can happen: timestamps are coarse on many file systems (a few milliseconds on Linux before 6.13, a second or more on some older or network ones), and the test sets the mtime back by hand to prove it.
- Without contents (`Version::of`), any change of identity, size or mtime is a conflict. A `chmod` isn't, which is why `ctime` isn't compared.

The hash is std's SipHash with fixed keys. It's for noticing accidental changes, not for security, and it isn't stable across Rust releases, so a version shouldn't be stored.

`Error::Conflict` also comes from an overwrite in place that finds a different file at the path than the one inspected when the save began, whether or not `unchanged_since` was used.

## Known gaps

- **The host side of a bind mount.** Saving on the host replaces the file, and the container keeps the old inode. Nothing on the host shows the file is mounted elsewhere. `Strategy::Overwrite` is the answer for such files.
- **`trusted.*` xattrs** aren't listed for a process without `CAP_SYS_ADMIN`, so they can't be copied or noticed.
- **Creation time on Linux** is lost by a replacement; there's no call to set it. It isn't counted as lost, or every replacement would become an overwrite.
- **Unix systems other than Linux and macOS** (FreeBSD, NetBSD, OpenBSD, illumos): extended attributes, ACLs and file flags aren't copied or detected, so a replacement loses them without saying so. Use `Strategy::Overwrite` there for files that have them.
- **macOS:**
  - document IDs (`UF_TRACKED`), file versions (`NSFileVersion`), and iCloud placeholder files aren't handled;
  - an inherited ACL isn't removed if the original has none, because `fcopyfile` decides that;
  - system attributes such as `com.apple.provenance` may refuse to be copied, which would turn every replace of such files into an overwrite. Check this on the first real run.
- **Windows:**
  - the owner SID may not survive `ReplaceFileW` when saving another user's file;
  - a backup the replace leaves that still can't be deleted after the retries stays, under the target's name;
  - see "Windows" above for durability.
- **Network file systems:** rename atomicity on NFS holds per client, and some FUSE file systems (sshfs without `-o workaround=rename`) refuse to rename over a file. Auto then overwrites. `flock` may not lock on some of them, in which case overwrites carry on unlocked.
- **Concurrent writers:**
  - Replacements: the last one wins, whole. `unchanged_since` tells a writer it lost the race, except within the small window before the rename.
  - Overwrites in place by saveguard take turns.
  - Other programs writing the same file at the same time aren't stopped.

## What others do

- **Vim** `backupcopy=auto`: renames only "when renaming the file is possible without side effects (the attributes can be passed on and the file is not a link)". That's this library's rule, minus the attributes Vim doesn't know about.
- **GLib** `g_file_replace` (`gio/glocalfileoutputstream.c`): renames unless the file has hard links, is a symlink, or the permissions or owner can't be set, then falls back to writing in place. It has etags for conflict detection. It's the closest prior art, but it's tied to GLib and Unix, and its replace path doesn't copy xattrs or ACLs.
- **Qt** `QSaveFile`: temp file and rename, with `setDirectWriteFallback` for unwritable directories.
- **Emacs:** `backup-by-copying`, `-when-linked`, `-when-mismatch`, `-when-privileged-mismatch`, and `file-precious-flag`.
- **`renameio`** (Go), **`atomic-write-file`** (Rust), **`write-file-atomic`** (Node): the rename half, with permissions at most. `atomic-write-file` documents that it replaces symlinks, and `renameio` doesn't support Windows.
