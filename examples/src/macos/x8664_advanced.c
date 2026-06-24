/*
 * An advanced macOS test program for the no-dyld example
 * (examples/hello_x8664_macos_advanced_nodyld.py).
 *
 * Leverages a broad set of libSystem functions to stress the no-dyld path:
 * printf / fprintf(stdout,stderr) / fputs / putchar, malloc / calloc / realloc /
 * free, qsort WITH A COMPARATOR CALLBACK, the fortified __*_chk string/mem
 * helpers, strlen/strchr/strrchr/strstr/strcmp/strncmp/memcmp, toupper/tolower/
 * isdigit, strtol/atoi/abs, snprintf/sprintf, getenv, getpid/getuid/time, and the
 * stack protector. It also imports the data symbols __stdoutp / __stderrp /
 * ___stack_chk_guard.
 *
 * Build (on a macOS host with the Xcode command-line tools):
 *   ./examples/scripts/build_macos_advanced.sh
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>

static int cmp_desc(const void *a, const void *b) {
    int x = *(const int *)a, y = *(const int *)b;
    return (x < y) - (x > y);   /* descending */
}

int main(int argc, char **argv) {
    /* stdio: printf, fprintf(stdout/stderr), putchar, puts */
    printf("== advanced libSystem test ==\n");
    fprintf(stdout, "fprintf stdout: argc=%d\n", argc);
    fprintf(stderr, "fprintf stderr: pid=%d\n", getpid());
    fputs("fputs line\n", stdout);
    putchar('!'); putchar('\n');

    /* heap churn: malloc / realloc / calloc / memcpy / free */
    int *a = malloc(8 * sizeof(int));
    for (int i = 0; i < 8; i++) a[i] = (i * 37 + 11) % 50;
    a = realloc(a, 10 * sizeof(int));
    a[8] = 3; a[9] = 99;
    int *b = calloc(10, sizeof(int));
    memcpy(b, a, 10 * sizeof(int));

    /* qsort with a comparator callback (descending) */
    qsort(b, 10, sizeof(int), cmp_desc);
    printf("sorted desc:");
    for (int i = 0; i < 10; i++) printf(" %d", b[i]);
    putchar('\n');

    /* strings + conversions */
    char buf[64];
    strcpy(buf, "qiling");
    strcat(buf, "-framework");
    char dup[64];
    strncpy(dup, buf, sizeof(dup));
    memmove(dup + 0, dup, strlen(dup) + 1);
    printf("str=%s len=%zu upper=%c lower=%c isdigit('5')=%d\n",
           buf, strlen(buf), toupper(buf[0]), tolower('Q'), isdigit('5'));
    printf("strchr=%s strstr=%s strrchr=%s\n",
           strchr(buf, '-'), strstr(buf, "frame"), strrchr(buf, 'i'));
    printf("strcmp=%d strncmp=%d memcmp=%d\n",
           strcmp("ab", "ac"), strncmp("abc", "abd", 2), memcmp("xy", "xy", 2));

    long n = strtol("  -1234zzz", NULL, 10);
    printf("strtol=%ld atoi=%d abs=%d\n", n, atoi("567"), abs(-42));

    char sb[64];
    snprintf(sb, sizeof(sb), "snprintf[%d,%s]", 7, "ok");
    sprintf(buf, "sprintf<%x>", 0xABCD);
    printf("%s %s\n", sb, buf);

    /* environment + ids + time */
    printf("getenv(PATH)=%s getuid=%d\n", getenv("PATH") ? "set" : "unset", getuid());
    time_t t = time(NULL);
    printf("time!=0 -> %d\n", t != 0);

    free(a);
    free(b);
    printf("done\n");
    return 0;
}
