/* guard_corrupt.c  —  self-CORRUPTING enforcement example for envcheck.
 *
 * This is a variant of guard.c. Same idea — run the environment checks and, if
 * the COMBINED score reaches a threshold, make the binary unusable so an analyst
 * can't keep poking at it — but instead of DELETING its own executable it
 * OVERWRITES its own executable's contents with a random value (0..9999),
 * truncating the file to that handful of bytes. Nothing but its OWN executable
 * image is ever touched.
 *
 * Why a variant: some AV/EDR vendors flag "a program that deletes its own
 * executable" as malware-like behaviour. Overwriting in place is a gentler
 * anti-tamper signal and leaves a corrupt-but-present file.
 *
 * ============== IMPORTANT: how the overwrite actually happens ==============
 *  A RUNNING executable cannot rewrite its own on-disk image directly:
 *    * Linux   -> open()/truncate() on the running image fail with ETXTBSY
 *                 ("text file busy").
 *    * Windows -> the image file is locked for writing while the process runs.
 *  So, exactly like guard.c hands its delete to a detached helper, this hands
 *  the overwrite to a detached helper that waits for THIS process to exit and
 *  then rewrites the file. The parent returns/-exits immediately after arming
 *  it. Net effect: the moment the guarded process ends, its binary on disk is
 *  clobbered.
 * ===========================================================================
 *
 * Same shipping caveats as guard.c apply:
 *  * GUARD_THRESHOLD (default 7) is LOW — ordinary VMs/CI score well above it,
 *    so this will corrupt the binary on many legitimate users' machines. Tune it
 *    against your real fleet, and prefer gating on analysis_score over vm_score.
 *  * Test with GUARD_DRY_RUN=1 first — it reports what it WOULD do, touching
 *    nothing.
 *
 * Build:  cc -O2 -Iinclude examples/guard_corrupt.c src/envcheck.c -o guard_corrupt
 *         cl /O2 /Iinclude examples\guard_corrupt.c src\envcheck.c      (Windows)
 */
#include "envcheck.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

/* The combined-score threshold at which the binary self-corrupts. */
#ifndef GUARD_THRESHOLD
#define GUARD_THRESHOLD 7
#endif

#if defined(_WIN32)
#  include <windows.h>
#  include <shellapi.h>
#  pragma comment(lib, "shell32.lib")
#else
#  include <unistd.h>
#endif

/* Resolve this process's own executable path. */
static int self_path(char *out, size_t n){
#if defined(_WIN32)
    DWORD r = GetModuleFileNameA(NULL, out, (DWORD)n);
    return (r>0 && r<n) ? 0 : -1;
#else
    ssize_t r = readlink("/proc/self/exe", out, n-1);
    if (r <= 0) return -1;
    out[r] = '\0';
    char *tag = strstr(out, " (deleted)");
    if (tag) *tag = '\0';
    return 0;
#endif
}

/* Arrange for this process's own executable to be overwritten with a random
   value (0..9999) once this process has exited. Returns 0 on success/scheduled. */
static int self_corrupt(const char *path){
    srand((unsigned)time(NULL) ^ (unsigned)(uintptr_t)&path);
    int value = rand() % 10000;   /* the "random number from 0 to 9999" */

#if defined(_WIN32)
    /* Detached cmd: wait a beat for us to exit (releasing the file lock), then
       overwrite the whole file with the number via redirection. */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "/c ping 127.0.0.1 -n 2 >nul & >\"%s\" echo %d", path, value);
    HINSTANCE h = ShellExecuteA(NULL, "open", "cmd.exe", cmd, NULL, SW_HIDE);
    return ((INT_PTR)h > 32) ? 0 : -1;
#else
    /* A running ELF is ETXTBSY, so hand the overwrite to a detached /bin/sh that
       waits for our PID to exit, then writes the number as the file's entire
       content (truncating the binary to those few bytes). */
    char cmd[4096];
    snprintf(cmd, sizeof(cmd),
             "n=0; while kill -0 %ld 2>/dev/null && [ $n -lt 400 ]; do "
             "n=$((n+1)); sleep 0.05; done; printf '%%s' '%d' > '%s'",
             (long)getpid(), value, path);
    pid_t pid = fork();
    if (pid == 0){
        setsid();                          /* detach so we survive parent exit */
        execl("/bin/sh", "sh", "-c", cmd, (char*)NULL);
        _exit(127);                        /* exec failed */
    }
    return (pid > 0) ? 0 : -1;
#endif
}

int main(void){
    int dry = 0;
    { const char *e = getenv("GUARD_DRY_RUN"); if (e && *e && *e!='0') dry = 1; }

    env_report_t r = env_inspect(NULL);
    int total = r.vm_score + r.analysis_score;

    if (total >= GUARD_THRESHOLD){
        char path[4096];
        int havep = (self_path(path, sizeof(path)) == 0);

        if (dry){
            fprintf(stderr,
                "[guard] DRY RUN: combined score %d >= %d — WOULD overwrite \"%s\" "
                "with a random value and exit.\n",
                total, GUARD_THRESHOLD, havep ? path : "(unknown path)");
            return 3;   /* dry-run signals the trip without acting */
        }

        /* Live: arm the overwrite of our own binary, then halt immediately. */
        if (havep) self_corrupt(path);

#if defined(_WIN32)
        ExitProcess(1);
#else
        _exit(1);
#endif
    }

    /* ---- Environment considered clean: your real program starts here. ---- */
    printf("environment OK (combined score %d < %d) — continuing.\n",
           total, GUARD_THRESHOLD);
    /* ... real application logic ... */
    return 0;
}
