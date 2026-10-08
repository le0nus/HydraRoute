#ifndef CONFIG_H
#define CONFIG_H

#include "hrneo.h"

int config_read(const char *path, config_t *cfg);
int config_generate(const char *target);
int config_flush_ipsets_on_start(const config_t *cfg);

typedef enum {
    KTOKEN_ADDED,
    KTOKEN_UPDATED,
    KTOKEN_UNCHANGED,
    KTOKEN_INVALID,
    KTOKEN_IO_ERROR
} keenetic_token_result_t;

keenetic_token_result_t config_set_keenetic_token(const char *path, const char *token);

#endif
