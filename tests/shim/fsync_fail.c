/* A failing fsync, for tests/engine_wire.py (docs/m3-engine.md 6bm): loaded with LD_PRELOAD, the FSYNC_FAIL_AT-th call of fsync in the process answers -1 with
 * EIO and writes nothing through; every other call is the real one. The calls AFTER the failing one succeed, as they may on Linux after an error was reported
 * once: a server that tried again would be told all is well.
 * FSYNC_COUNT_FILE, if set, gets the number of calls made so far, rewritten at each call, for the test to read how far the process went. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int calls = 0;

int fsync(int fd) {
    static int (*real)(int) = 0;
    if (!real) real = (int (*)(int))dlsym(RTLD_NEXT, "fsync");
    calls++;
    const char *note = getenv("FSYNC_COUNT_FILE");
    if (note) {
        int n = open(note, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (n >= 0) {
            char buf[32];
            int len = snprintf(buf, sizeof buf, "%d\n", calls);
            if (write(n, buf, len) < 0) { }
            close(n);
        }
    }
    const char *at = getenv("FSYNC_FAIL_AT");
    if (at && atoi(at) == calls) {
        errno = EIO;
        return -1;
    }
    return real(fd);
}
