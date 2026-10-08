# CLAUDE.md

saveguard saves files without wrecking them: it replaces a file atomically when nothing about it would be lost, and otherwise overwrites it in place from a complete staged copy, and reports what it did. A Rust library, a CLI and a C API.

- **`docs/status.md` is the handoff: read it first.** It covers what's verified, how to test (including the cross-target clippy runs that are the only check macOS and Windows get locally), and what's next.
- `docs/design.md` explains every case the library handles, how it's detected, and why it's done that way. Update it with any behaviour change.
- `README.md` is for users.

Rules that are easy to break:

- On any error except `Error::Interrupted`, the target must be untouched and the staged file removed. Tests check `leftovers()`.
- Every behaviour claim in the docs should be backed by a test on real files, or marked untested.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
