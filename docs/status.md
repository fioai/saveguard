# Status

Where saveguard stands, how to work on it, and what's next. Read this first.

## State (2026-10-08)

Version 0.1.0, public at https://github.com/fioai/saveguard under the MIT license, not yet on crates.io. Three crates:

- `crates/saveguard`: the library, with no dependencies beyond `libc` / `windows-sys`.
  - `writer.rs`: the decision (`decide`) and the save itself (`open`, `Pending::commit`).
  - `sys/unix.rs`, `sys/windows.rs`: the platform halves.
  - `resolve.rs`: symlinks. `version.rs`: conflicts.
- `crates/saveguard-cli`: the `saveguard` binary (`write`, `plan`).
- `crates/saveguard-capi`: `libsaveguard` and `include/saveguard.h`.

What's been verified, and how:

- **Linux:** everything, on ext4 and tmpfs, as an ordinary user.
  - Bind mounts and a full disk are tested in user namespaces (`unshare -rm`). The `/tmp` symlink attack is tested with two users (`unshare --map-auto --map-root-user`, which needs `/etc/subuid`).
  - Mutation checks (break the fix, watch the test fail) were done for the space reservation, the overwrite lock, the identity check before overwriting, and the shared-directory rule.
  - The setuid rule is the kernel's, read from `fs/attr.c` (`!capable(CAP_FSETID)`). A user-namespace experiment had suggested otherwise; see `docs/design.md`. Capability clearing was checked against the 6.18 kernel.
- **Review:** an adversarial review agent went over everything on 2026-10-08 and found 15 problems, 2 of them security issues, plus some minor ones. All were fixed, with a regression test wherever this machine can run one (so not the Windows and macOS fixes). The exception is the Unix systems other than Linux and macOS, which are documented as a gap instead.
- **macOS and Windows:** CI (`.github/workflows/ci.yml`, GitHub Actions) runs every test on both on each push, green since 2026-10-08. Each has tests of its own (`tests/macos.rs`, `tests/windows.rs`).
  - macOS passed from the first run.
  - Windows needed a redesign. `ReplaceFileW` turned out not to be atomic (a reader found no file mid-save), so Windows now copies the metadata and renames atomically like Unix.
  - Then the ACL matching had to learn that a replaced file's ACL can read as explicit copies of inherited entries. `docs/design.md` has the story.
  - Locally the other platforms only get `cargo clippy --target …`.
- **Not tested:** running as real root, NFS, FUSE, btrfs-specific flags (`+C`), SELinux labels.

## How to work

```sh
cargo test --workspace                       # ~5 s; the C API test builds the cdylib itself
cargo clippy --workspace --all-targets -- -D warnings
for t in x86_64-pc-windows-gnu aarch64-apple-darwin; do
  cargo clippy --workspace --all-targets --target $t -- -D warnings
done                                         # the only check the other platforms get locally
cargo fmt --all
```

- Tests that need something this machine may lack skip themselves with a message (`skipped: ...`), so read the `--nocapture` output after changing a platform path. Examples: `setfacl`, user xattrs, file flags, user namespaces (off on Ubuntu runners since 23.10).
- Keep tests on real files: the point is what file systems do, not what we think they do. The decision itself is the pure function `writer::decide`, unit-tested in `writer.rs`.
- Any new way of losing something gets a test that would fail without the fix. Then check the test by breaking the fix on purpose, as was done for the space reservation, the lock, the identity check and the shared-directory rule. The lock test needed bigger files before it could catch anything.

## Next

1. Things CI doesn't cover yet:
   - macOS system xattrs like `com.apple.provenance` (if they can't be copied, every replace of such files becomes an overwrite);
   - Windows owner mismatches (another user's file);
   - Windows compression and encryption.
2. Publish to crates.io once CI is green on all three platforms (ask first: it can't be undone).
3. Fault-injection tests for the paths real file systems rarely take:
   - an xattr that won't copy, which should turn into an overwrite;
   - a rename refused for reasons other than a bind mount;
   - an `Interrupted` error caught in a test rather than only by the mutation check.
4. Bindings that use the C API: Python (`ctypes`) and Node are the obvious first two.
5. Linux `O_TMPFILE` staging for replaces, so a crash mid-replace leaves no `.saveguard-*.tmp` behind. Not for overwrites in place: there the staged file is what a crash is recovered from.
6. MSRV: probably 1.77 (C string literals); check it, then put `rust-version` in Cargo.toml.
