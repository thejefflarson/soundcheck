/* Test case: memory-api-misuse (CWE-690, CWE-415, CWE-401, CWE-403)
 *
 * This file contains several function-local memory and resource API misuses.
 * Invoking memory-api-misuse should flag each one and propose a secure
 * rewrite that checks the return, frees once, initializes locks before use,
 * and closes fds across exec.
 */

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

/* BUG 1 (CWE-690): malloc return not checked before memcpy */
char *copy_chunk(const char *src, size_t n) {
    char *p = malloc(n);
    memcpy(p, src, n);
    return p;
}

/* BUG 2 (CWE-401): realloc overwriting original pointer; leak on NULL */
void grow_buffer(char **bufp, size_t *cap, size_t new_cap) {
    *bufp = realloc(*bufp, new_cap);
    *cap = new_cap;
}

/* BUG 3 (CWE-415): free on both error and cleanup paths */
int process(const char *src, size_t n) {
    char *buf = malloc(n);
    if (buf == NULL) return -1;
    if (memcmp(src, "MAGIC", 5) != 0) {
        free(buf);
        goto out;
    }
    memcpy(buf, src, n);
out:
    free(buf);
    return 0;
}

/* BUG 4 (CWE-665): mutex used without init */
struct cache {
    pthread_mutex_t lock;
    int hits;
};

void cache_hit(struct cache *c) {
    pthread_mutex_lock(&c->lock);
    c->hits++;
    pthread_mutex_unlock(&c->lock);
}

/* BUG 5 (CWE-403): fopen without O_CLOEXEC; fd leaks into exec'd children */
FILE *read_config(const char *path) {
    FILE *f = fopen(path, "r");
    return f;
}

/* BUG 6 (CWE-690): mmap return MAP_FAILED not checked */
void *load_region(int fd, size_t len) {
    void *p = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
    memcpy((char *)p, "first byte preview", 18);
    return p;
}
