/*
 * saveguard: save files without wrecking them.
 *
 * Replaces a file atomically when nothing about it would be lost, and otherwise overwrites it in
 * place (hard links, mount points, an owner or attributes a new file couldn't have), from a
 * complete copy of the new contents written first. Symlinks are followed to the file they point
 * to. Every save says how it went in a saveguard_report.
 *
 * All functions are thread-safe. Paths are bytes on Unix and UTF-8 on Windows. Functions return
 * SAVEGUARD_OK (0) or a negative SAVEGUARD_ERR_* code; saveguard_last_error() then describes the
 * failure, for the calling thread.
 */
#ifndef SAVEGUARD_H
#define SAVEGUARD_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A snapshot of a file, for noticing later that it changed. Only meaningful to saveguard, and
 * only within the process that made it. Get one from saveguard_read(), saveguard_version_of() or
 * a saveguard_report. */
typedef struct saveguard_version {
    uint64_t opaque[8];
} saveguard_version;

/* saveguard_options.strategy */
#define SAVEGUARD_AUTO 0      /* replace when nothing would be lost, else overwrite (default) */
#define SAVEGUARD_REPLACE 1   /* always replace, reporting what's lost */
#define SAVEGUARD_OVERWRITE 2 /* always write into the existing file */

/* saveguard_options.flags */
#define SAVEGUARD_NO_FOLLOW 0x1u  /* replace a symlink itself, not the file it points to */
#define SAVEGUARD_NO_SYNC 0x2u    /* don't wait for the disk */
#define SAVEGUARD_CREATE_NEW 0x4u /* fail with SAVEGUARD_ERR_EXISTS if the file exists */

typedef struct saveguard_options {
    uint32_t strategy;
    uint32_t flags;
    /* Permissions for a file that doesn't exist yet, before the umask; 0 means 0666. */
    uint32_t mode;
    /* Fail with SAVEGUARD_ERR_CONFLICT unless the file is still this version. NULL: no check. */
    const saveguard_version *unchanged_since;
} saveguard_options;

/* saveguard_report.method */
#define SAVEGUARD_CREATED 1   /* there was no file */
#define SAVEGUARD_REPLACED 2  /* a new file was renamed over the old one, atomically */
#define SAVEGUARD_OVERWROTE 3 /* the new contents were written into the existing file */

/* saveguard_report.reasons: why it was overwritten in place */
#define SAVEGUARD_REASON_REQUESTED 0x01u
#define SAVEGUARD_REASON_HARD_LINKS 0x02u
#define SAVEGUARD_REASON_MOUNT_POINT 0x04u
#define SAVEGUARD_REASON_DIRECTORY_NOT_WRITABLE 0x08u
#define SAVEGUARD_REASON_OWNER 0x10u
#define SAVEGUARD_REASON_GROUP 0x20u
#define SAVEGUARD_REASON_METADATA 0x40u
#define SAVEGUARD_REASON_RENAME_FAILED 0x80u

/* saveguard_report.lost: what the file had before that it doesn't now */
#define SAVEGUARD_LOST_HARD_LINKS 0x001u
#define SAVEGUARD_LOST_OWNER 0x002u
#define SAVEGUARD_LOST_GROUP 0x004u
#define SAVEGUARD_LOST_PERMISSIONS 0x008u
#define SAVEGUARD_LOST_SETID 0x010u
#define SAVEGUARD_LOST_CAPABILITIES 0x020u
#define SAVEGUARD_LOST_ACL 0x040u
#define SAVEGUARD_LOST_SECURITY_LABEL 0x080u
#define SAVEGUARD_LOST_XATTR 0x100u
#define SAVEGUARD_LOST_FLAGS 0x200u

typedef struct saveguard_report {
    uint32_t method;
    uint32_t reasons;
    uint32_t lost;
    /* The file after the save, for the next save's unchanged_since. Zero from saveguard_plan(). */
    saveguard_version version;
} saveguard_report;

/* Return values */
#define SAVEGUARD_OK 0
#define SAVEGUARD_ERR_IO (-1)           /* see saveguard_last_os_error() */
#define SAVEGUARD_ERR_CONFLICT (-2)     /* the file changed since unchanged_since */
#define SAVEGUARD_ERR_EXISTS (-3)       /* SAVEGUARD_CREATE_NEW and the file exists */
#define SAVEGUARD_ERR_NOT_A_FILE (-4)   /* a directory, device, ... */
#define SAVEGUARD_ERR_READ_ONLY (-5)    /* the file can't be written by this process */
#define SAVEGUARD_ERR_SYMLINK_LOOP (-6)
#define SAVEGUARD_ERR_INTERRUPTED (-7)  /* overwriting failed partway: see saveguard_last_error() */
#define SAVEGUARD_ERR_INVALID (-8)      /* a bad argument */

/* Saves len bytes from data to the file at path. options and report may be NULL. */
int saveguard_save(const char *path, const void *data, size_t len,
                   const saveguard_options *options, saveguard_report *report);

/* Says how saveguard_save() would go, without writing anything. */
int saveguard_plan(const char *path, const saveguard_options *options, saveguard_report *report);

/* Reads the whole file into a new buffer, to be freed with saveguard_free(), and the version that
 * was read (with a hash of the contents). version may be NULL. */
int saveguard_read(const char *path, uint8_t **data, size_t *len, saveguard_version *version);

/* Frees a buffer from saveguard_read(). NULL is ignored. */
void saveguard_free(uint8_t *data);

/* The file's version from its metadata alone; a missing file gives the "absent" version. */
int saveguard_version_of(const char *path, saveguard_version *version);

/* What the last failing call on this thread failed with, or "" if none has. Valid until the next
 * call on this thread. */
const char *saveguard_last_error(void);

/* The operating system's error code (errno, or GetLastError() on Windows) behind the last failing
 * call on this thread, or 0. */
int saveguard_last_os_error(void);

#ifdef __cplusplus
}
#endif

#endif /* SAVEGUARD_H */
