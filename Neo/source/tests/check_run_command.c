#include "../include/util.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    const char *batch = "*mangle\n-D PREROUTING -j GONE\nCOMMIT\n";
    char err[64];

    /* iptables-restore names the failing line on stderr; keep the first line. */
    char *fail[] = {"sh", "-c", "cat >/dev/null; echo 'line 2 failed' >&2; echo more >&2; exit 2", NULL};
    assert(run_command_stdin("sh", fail, batch, strlen(batch), err, sizeof(err)) == 2);
    assert(strcmp(err, "line 2 failed") == 0);

    /* The input reaches the command; a quiet success leaves err empty. */
    char *ok[] = {"sh", "-c", "grep -q '^COMMIT$'", NULL};
    assert(run_command_stdin("sh", ok, batch, strlen(batch), err, sizeof(err)) == 0);
    assert(err[0] == '\0');

    /* Stdout is not part of the error. */
    char *chatty[] = {"sh", "-c", "cat; exit 1", NULL};
    assert(run_command_stdin("sh", chatty, batch, strlen(batch), err, sizeof(err)) == 1);
    assert(err[0] == '\0');

    /* A long stderr is cut to the buffer and still drained, so the command
     * cannot block on a full pipe. */
    char *noisy[] = {"sh", "-c",
                     "cat >/dev/null; yes 'Another app is currently holding the xtables lock' | head -n 5000 >&2; exit 4",
                     NULL};
    assert(run_command_stdin("sh", noisy, batch, strlen(batch), err, sizeof(err)) == 4);
    assert(strncmp(err, "Another app is currently holding", 32) == 0);
    assert(strlen(err) < sizeof(err));

    puts("check_run_command: OK");
    return 0;
}
