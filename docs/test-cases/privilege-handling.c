/* Test case: privilege-handling (CWE-271, CWE-426, CWE-377, CWE-61)
 *
 * Each function below is a SUID-installed helper with a classic privilege
 * gap. Invoking privilege-handling should flag each one and rewrite to use
 * setresuid with checks, scrubbed env + absolute path for exec, atomic
 * mkostemp for temp files, and O_NOFOLLOW on world-writable paths.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* BUG 1 (CWE-271): setuid alone leaves saved set-user-ID intact.
 * Process can seteuid(0) itself back. No return-value check. */
void drop_privs(void) {
    setuid(getuid());
}

/* BUG 2 (CWE-426): system() resolves "logger" via inherited PATH.
 * Attacker sets PATH=/tmp; drops /tmp/logger; gets root. */
void log_event(const char *msg) {
    char cmd[512];
    snprintf(cmd, sizeof cmd, "logger '%s'", msg);
    system(cmd);
}

/* BUG 3 (CWE-377): tmpnam returns a name; window between name and fopen
 * is a TOCTOU race. */
FILE *new_workfile(void) {
    char *name = tmpnam(NULL);
    return fopen(name, "w");
}

/* BUG 4 (CWE-61): open in /tmp without O_NOFOLLOW. Attacker pre-creates
 * /tmp/audit.log as a symlink to /etc/passwd. */
int write_audit(const char *line) {
    int fd = open("/tmp/audit.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return -1;
    write(fd, line, strlen(line));
    close(fd);
    return 0;
}

/* BUG 5 (CWE-732): no umask set; created files inherit caller umask which
 * may be 0. */
int spool_file(const char *path, const char *body) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (fd < 0) return -1;
    write(fd, body, strlen(body));
    close(fd);
    return 0;
}
