/* Exercises the C API from C. Run with a scratch directory as the only argument. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "saveguard.h"

static int failures = 0;

#define CHECK(cond)                                                                     \
    do {                                                                                \
        if (!(cond)) {                                                                  \
            fprintf(stderr, "%s:%d: failed: %s (last error: %s)\n", __FILE__, __LINE__, \
                    #cond, saveguard_last_error());                                     \
            failures++;                                                                 \
        }                                                                               \
    } while (0)

static void write_file(const char *path, const char *text) {
    FILE *f = fopen(path, "w");
    fputs(text, f);
    fclose(f);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: smoke DIR\n");
        return 2;
    }
    char path[4096], other[4096];
    snprintf(path, sizeof path, "%s/a.txt", argv[1]);
    snprintf(other, sizeof other, "%s/b.txt", argv[1]);
    saveguard_report report;

    /* Created, then replaced. */
    CHECK(saveguard_save(path, "one", 3, NULL, &report) == SAVEGUARD_OK);
    CHECK(report.method == SAVEGUARD_CREATED);
    CHECK(saveguard_save(path, "two", 3, NULL, &report) == SAVEGUARD_OK);
    CHECK(report.method == SAVEGUARD_REPLACED && report.reasons == 0 && report.lost == 0);

    /* A second hard link: overwritten in place, both names see it. */
    CHECK(link(path, other) == 0);
    CHECK(saveguard_save(path, "three", 5, NULL, &report) == SAVEGUARD_OK);
    CHECK(report.method == SAVEGUARD_OVERWROTE);
    CHECK(report.reasons == SAVEGUARD_REASON_HARD_LINKS);
    uint8_t *data = NULL;
    size_t len = 0;
    saveguard_version version;
    CHECK(saveguard_read(other, &data, &len, &version) == SAVEGUARD_OK);
    CHECK(len == 5 && memcmp(data, "three", 5) == 0);
    saveguard_free(data);

    /* Someone else changes it after we read it: a conflict, and their change stays. */
    write_file(path, "theirs");
    saveguard_options options = {SAVEGUARD_AUTO, 0, 0, &version};
    CHECK(saveguard_save(path, "mine", 4, &options, NULL) == SAVEGUARD_ERR_CONFLICT);
    CHECK(strstr(saveguard_last_error(), "changed on disk") != NULL);

    /* The report's version guards the next save. */
    options.unchanged_since = NULL;
    CHECK(saveguard_save(path, "four", 4, &options, &report) == SAVEGUARD_OK);
    options.unchanged_since = &report.version;
    CHECK(saveguard_save(path, "five", 4, &options, &report) == SAVEGUARD_OK);

    /* Create-new, plan, version_of. */
    saveguard_options create_new = {SAVEGUARD_AUTO, SAVEGUARD_CREATE_NEW, 0644, NULL};
    CHECK(saveguard_save(path, "x", 1, &create_new, NULL) == SAVEGUARD_ERR_EXISTS);
    CHECK(saveguard_plan(path, NULL, &report) == SAVEGUARD_OK);
    CHECK(report.method == SAVEGUARD_OVERWROTE);
    CHECK(saveguard_version_of(path, &version) == SAVEGUARD_OK);

    /* Bad arguments. */
    saveguard_options bad = {7, 0, 0, NULL};
    CHECK(saveguard_save(path, "x", 1, &bad, NULL) == SAVEGUARD_ERR_INVALID);
    CHECK(saveguard_save(NULL, "x", 1, NULL, NULL) == SAVEGUARD_ERR_INVALID);
    saveguard_version garbage;
    memset(&garbage, 0, sizeof garbage);
    saveguard_options stale = {SAVEGUARD_AUTO, 0, 0, &garbage};
    CHECK(saveguard_save(path, "x", 1, &stale, NULL) == SAVEGUARD_ERR_INVALID);

    /* A directory isn't a file; a missing directory is an I/O error with errno. */
    CHECK(saveguard_save(argv[1], "x", 1, NULL, NULL) == SAVEGUARD_ERR_NOT_A_FILE);
    char missing[4096];
    snprintf(missing, sizeof missing, "%s/no/such/file", argv[1]);
    CHECK(saveguard_save(missing, "x", 1, NULL, NULL) == SAVEGUARD_ERR_IO);
    CHECK(saveguard_last_os_error() != 0);

    if (failures == 0) printf("ok\n");
    return failures == 0 ? 0 : 1;
}
