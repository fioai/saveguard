# saveguard

Save files without wrecking them.

Replacing a file's contents looks like a one-liner, but there are only two ways to do it, and each one breaks something:

- **Overwrite in place.** A crash or a full disk halfway through leaves a truncated file.
- **Write a temporary file and rename it over the original.** This is what "atomic write" libraries do. It's crash-safe, but the result is a *new* file. Hard links stop sharing it, a symlink becomes a plain file, and a file owned by someone else becomes yours. ACLs, extended attributes, SELinux labels and `chattr` flags disappear. On a Docker bind-mounted file the rename fails outright: that's the classic `sed -i` "Device or resource busy".

Which way is right depends on the file. You can tell no library has owned that decision, because tool after tool exposes it as a setting with its own name:

- Vim: `backupcopy`
- Emacs: `backup-by-copying-when-linked` and its siblings
- JetBrains: "safe write"
- GNU sed: `--follow-symlinks`
- rsync: `--inplace`

webpack's docs tell you to change your editor's setting so its file watcher works. And new tools keep getting it wrong: Claude Code's [#78162](https://github.com/anthropics/claude-code/issues/78162) is a settings writer that follows one symlink hop instead of all of them.

saveguard makes the decision per file:

- **It replaces atomically when nothing would be lost.** A complete new file is written next to the old one and given the old file's owner, group, permissions, ACL, extended attributes, security label and flags. It's flushed, then renamed into place.
- **Otherwise it overwrites in place.** It still writes a complete copy of the new contents first, so a crash can't lose them, and (on Linux) checks that there's room before it touches the file.
- **Every save returns a report** of what it did, why, and anything that couldn't be kept.

## Use

### Rust

```rust
let report = saveguard::save("settings.json", b"{}\n")?;
println!("{report}"); // "replaced settings.json"
```

A program that holds a file open for a while, like an editor, should hand back the version it read. A save then fails with `Error::Conflict` instead of silently discarding someone else's change:

```rust
use saveguard::Options;

let (text, version) = saveguard::read("notes.txt")?;
// ... the user edits ...
let report = Options::new().unchanged_since(&version).save("notes.txt", &text)?;
// report.version guards the next save
```

You can also write big contents in pieces, check what a save would do, or force a strategy:

```rust
use std::io::Write;
use saveguard::{Options, Strategy};

let mut w = Options::new().open("big.log")?;
w.write_all(b"...")?;
w.commit()?; // nothing happens to big.log before this; dropping `w` abandons the save

let plan = Options::new().plan("/etc/hosts")?;   // in a container: "would overwrite /etc/hosts in place (the file is a mount point)"
Options::new().strategy(Strategy::Overwrite).save("disk.img", &bytes)?;
```

### Command line

```sh
sort notes.txt | saveguard write notes.txt     # like sponge: the input is read in full first
saveguard plan ~/.bashrc                       # say how it would be saved, without writing
```

### C, and anything with a C FFI

`crates/saveguard-capi` builds `libsaveguard` (shared and static). The API is in [`saveguard.h`](crates/saveguard-capi/include/saveguard.h).

```c
saveguard_report report;
if (saveguard_save("notes.txt", data, len, NULL, &report) != SAVEGUARD_OK)
    fprintf(stderr, "%s\n", saveguard_last_error());
```

## What it handles

| The file is… | A rename would… | saveguard |
|---|---|---|
| reached through symlinks | replace the link with a plain file, or (stopping after one hop) fail in a read-only directory | follows every hop and saves the file at the end; links stay links |
| hard-linked | leave the other names with the old contents | overwrites in place |
| a bind mount (Docker) | fail with `EBUSY` | overwrites in place (found with `statx`, because a same-filesystem bind mount has the same device number as its folder) |
| in a directory you can't write | fail | overwrites in place, staging the new contents in the temp directory |
| owned by another user, or a group you're not in | take ownership | overwrites in place |
| given an ACL, xattrs, an SELinux label or `chattr` flags | drop them | copies them; if any won't copy, overwrites in place |
| in a directory with a default ACL | give the new file an ACL the old one didn't have | removes it |
| private (`0600`) | expose the new contents while they're written, if the temp file is created with the default mode | stages them in a private file |
| setuid, or has file capabilities | carry privileges over to contents nobody vetted | clears them, as the kernel does for a write in place, and says so |
| changed by someone else since you read it | overwrite their change | `Error::Conflict` (with `unchanged_since`) |
| a symlink another user left in `/tmp` (or any sticky, world-writable directory) | let them choose which of your files gets overwritten | refuses, by the kernel's own rule (`fs.protected_symlinks`), which following links by hand would otherwise skip |
| being overwritten in place by two saves at once | (when overwriting) end up with the start of one and the end of the other | makes them take turns (a lock) |
| bigger after the save than the free space allows | (when overwriting) die halfway | finds out before touching the file (Linux) |

There's more, with the reasoning for each, in [docs/design.md](docs/design.md).

## Platforms

- **Linux:** tested, on ext4 and tmpfs. The bind-mount, full-disk and `/tmp` symlink-attack cases are tested in user namespaces.
- **macOS:** compiles and passes clippy, but hasn't been run yet. It handles xattrs through the system's own safe-save rules (`xattr_preserve_for_intent`), ACLs, `chflags`, and creation dates.
- **Windows:** compiles and passes clippy, but hasn't been run yet. It uses `ReplaceFileW`, which keeps attributes, ACLs and streams. It retries while virus scanners hold the file, and overwrites in place for hard links.
- **Other Unix systems** (the BSDs, illumos): saving works, but extended attributes, ACLs and file flags aren't copied or detected, so a replacement can lose them. Use `Strategy::Overwrite` for files that have them.

## Limits

- Atomic means the file is never seen half-written. A crash can still lose the *latest* save if the disk lies about flushing; saveguard asks for full flushes (`fsync`, `F_FULLFSYNC`) unless told `Durability::None`.
- Overwriting in place isn't atomic: other readers can see a mixture while it happens. That's the price of keeping the file's identity, and the report says when it happened. Two saveguard saves of the same file take turns, but other programs writing it at the same moment aren't stopped.
- The host side of a bind mount can't be detected. Saving on the host replaces the file, and the container keeps the old one. Use `Strategy::Overwrite` for files you know are mounted elsewhere.
- Extended attributes the process can't list (`trusted.*` without `CAP_SYS_ADMIN`) can't be copied or noticed.
- A file's creation time is lost by a replacement on Linux, where it can't be set.
- Versions are for the process that made them; they aren't meant to be stored.

## Prior art

saveguard collects what these already knew:

- [Vim's `backupcopy`](https://vimhelp.org/options.txt.html#%27backupcopy%27) and Emacs's `backup-by-copying-*` options
- [GLib's `g_file_replace`](https://gitlab.gnome.org/GNOME/glib/-/blob/main/gio/glocalfileoutputstream.c), which is the closest thing to this, but tied to GLib
- Qt's `QSaveFile`
- Windows' `ReplaceFileW` and macOS's `FileManager.replaceItemAt`
- the atomic-write libraries: `renameio`, `atomic-write-file`, `write-file-atomic`. They do the rename half.
