#ifndef _AES_TOOL_CRYPT_H_
#define _AES_TOOL_CRYPT_H_

#include "aes_context.h"

#include <stddef.h>

int aes_crypt_ecb(aes_context * ctx, int mode, size_t inputLen, uint8_t * input, uint8_t * output);

int aes_crypt_cbc(aes_context * ctx, int mode, size_t inputLen, uint8_t * input, uint8_t * output);

#endif //_AES_TOOL_CRYPT_H_
