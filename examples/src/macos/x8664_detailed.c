/*
 * A more detailed macOS test program for the no-dyld example
 * (examples/hello_x8664_macos_detailed_nodyld.py).
 *
 * Exercises a variety of libSystem imports: printf with several conversions,
 * the heap (malloc/free), string and memory routines, snprintf, a libc syscall
 * wrapper (getpid), a direct write(), and the stack protector.
 *
 * Build (on a macOS host with the Xcode command-line tools):
 *   clang -arch x86_64 -mmacosx-version-min=10.13 -O0 \
 *       -o ../rootfs/x8664_macos/bin/x8664_detailed x8664_detailed.c
 * or just run examples/scripts/build_macos_detailed.sh
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    printf("argc = %d\n", argc);
    for (int i = 0; i < argc; i++)
        printf("  argv[%d] = %s\n", i, argv[i]);

    /* integer / hex / char / string formatting (varargs) */
    printf("int=%d hex=0x%x char=%c str=%s\n", 42, 255, 'Q', "qiling");

    /* heap */
    char *buf = malloc(64);
    if (!buf) { printf("malloc failed\n"); return 1; }
    strcpy(buf, "heap-allocated");
    printf("buf = %s (len=%lu)\n", buf, (unsigned long)strlen(buf));

    /* string compare */
    printf("strcmp eq=%d ne=%d\n", strcmp("abc", "abc"), strcmp("abc", "abd"));

    /* memset / memcpy */
    char dst[16];
    memset(dst, 'A', 15); dst[15] = 0;
    printf("memset: %s\n", dst);
    memcpy(dst, "copied!", 8);
    printf("memcpy: %s\n", dst);

    /* snprintf */
    char sb[32];
    snprintf(sb, sizeof(sb), "sum=%d", 1 + 2 + 3 + 4 + 5);
    printf("snprintf: %s\n", sb);

    /* libc syscall wrapper */
    printf("getpid = %d\n", getpid());

    /* direct write() */
    const char *msg = "direct write()\n";
    write(1, msg, strlen(msg));

    free(buf);
    printf("done, returning 7\n");
    return 7;
}
