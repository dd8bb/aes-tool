#ifndef _AES_ENCRYPTION_TOOL_CORE_H_
#define _AES_ENCRYPTION_TOOL_CORE_H_


#include "aes_const.h"

#include <stdint.h>



void key_expansion(uint8_t * key, uint8_t * expandedKey, AES_t type);

void add_round_key(uint8_t * state, uint8_t * roundKey);

void sub_bytes(uint8_t * state);
void inv_sub_bytes(uint8_t * state);

void shift_rows(uint8_t * state);
void inv_shift_rows(uint8_t * state);

void mix_columns(uint8_t * state);
void inv_mix_columns(uint8_t * state);

#endif
