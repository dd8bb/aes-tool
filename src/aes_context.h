#ifndef _AES_ENCRYPTION_TOOL_CONTEXT_H_
#define _AES_ENCRYPTION_TOOL_CONTEXT_H_

#include "aes_const.h"

#include <stdint.h>

#define AES_TOOL_DEFAULT_IV (uint8_t[])\
    {0xF9, 0xAB, 0x46, 0x04, 0x32, 0x75, 0x52, 0xE0, \
     0x21, 0x8A, 0x4F, 0x5D, 0x25, 0x6D, 0xB7, 0x18}


/*
 *  AES Context Structure
 */
typedef struct {
	uint8_t key[AES256_KEY_LENGTH];
	uint8_t iv[AES_BLOCK_SIZE];
	uint8_t *rkeys;
	AES_t   flavour;
}aes_context;


void aes_ctx_init(aes_context * ctx);

void aes_ctx_free(aes_context * ctx);

int aes_ctx_set_key(aes_context * ctx, uint8_t * key, int length);

int aes_ctx_set_iv(aes_context * ctx, uint8_t * iv);


#endif //_AES_ENCRYPTION_TOOL_CONTEXT_H_
