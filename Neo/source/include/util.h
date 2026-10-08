#ifndef UTIL_H
#define UTIL_H

#include "hrneo.h"
#include <stdlib.h>
#include <string.h>

domain_hashtable_t *ht_create(void);
void ht_destroy(domain_hashtable_t *ht);
void ht_rank_targets(domain_hashtable_t *ht, const char (*order)[64], int count);
int ht_insert(domain_hashtable_t *ht, const char *domain, size_t domain_len, const char *ipset_name);
const ht_target_t *ht_lookup(const domain_hashtable_t *ht, const char *domain, size_t domain_len);

void to_lower_inplace(char *s, size_t len);
char *trim_whitespace(char *s);
int mkdir_p(const char *path, int mode);
int run_command_output(const char *cmd, char *const argv[], char *output, size_t output_size);
int run_command_stdin(const char *cmd, char *const argv[], const char *input, size_t input_len,
                      char *err, size_t err_size);
const char *line_find(const char *line, size_t line_len, const char *needle);
/* A /proc list of names, one per line (/proc/net/ip_tables_names): 1 if name
 * is listed, 0 if the whole list was read and it is not, -1 if unknown. */
int proc_list_has(const char *path, const char *name);
/* An exclusive flock on path (created if missing), taken without waiting
 * and held until the fd is closed or the process exits; the fd is
 * close-on-exec, so no command the holder runs keeps it. Returns the fd,
 * LOCK_HELD if another holder has it, or -1 with errno set. */
#define LOCK_HELD (-2)
int lock_acquire(const char *path);

#endif
