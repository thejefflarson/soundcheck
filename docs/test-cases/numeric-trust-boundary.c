/* Test case: numeric-trust-boundary (CWE-190, CWE-194, CWE-704, CWE-20)
 *
 * Each function below converts untrusted input into a numeric value
 * that flows into a length, size, index, or auth comparison without
 * a post-conversion bounds check. Invoking numeric-trust-boundary
 * should flag each one.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LEN 4096

/* BUG 1 (CWE-194 sign-extension): signed char promoted, cast to size_t
 * yields SIZE_MAX for header[0] = 0xFF. */
void *parse_record(const unsigned char *header, const unsigned char *src) {
    int len = (signed char)header[0];
    void *buf = malloc(len);
    memcpy(buf, src, len);
    return buf;
}

/* BUG 2 (CWE-20): atoi returns 0 silently on "banana" and on overflow.
 * Caller treats result as a valid permission ID. */
int authorize_user(const char *uid_str) {
    int uid = atoi(uid_str);   // "banana" → 0; "9999999999999" → INT_MAX
    if (uid == 0) return 1;    // user 0 has admin
    return uid_has_admin(uid);
}
int uid_has_admin(int uid);

/* BUG 3 (CWE-190 width-truncation in bounds check): (short)len narrows
 * 0x10000 to 0 which passes the check; full int len still used. */
int copy_chunk(const char *src, int len) {
    char buf[MAX_LEN];
    if ((short)len < MAX_LEN) {
        memcpy(buf, src, len);
        return 0;
    }
    return -1;
}

/* BUG 4 (CWE-190 wraparound): user_count * sizeof(struct foo) overflows
 * to a small total; malloc succeeds; memcpy writes huge amount. */
struct foo { char data[64]; };

void *load_batch(size_t user_count, const struct foo *src) {
    size_t total = user_count * sizeof(struct foo);
    void *p = malloc(total);
    if (p == NULL) return NULL;
    memcpy(p, src, user_count * sizeof(struct foo));
    return p;
}

/* BUG 5 (CWE-20): negative index passes (int)0 < N check via signed
 * comparison, but indexing the array with -1 reads upstream memory. */
int permission_for(int role_id) {
    static int role_table[16] = {0};
    if (role_id < 16) {
        return role_table[role_id];   // role_id = -1 reads role_table[-1]
    }
    return 0;
}

/* BUG 6 (CWE-369 divide-by-zero): user-controlled divisor, no check. */
int per_chunk_size(int total, int user_chunks) {
    return total / user_chunks;
}
