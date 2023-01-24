#include "aes_context.h"

#include "aes_core.h"

#include <string.h>
#include <stdlib.h>

void aes_ctx_init(aes_context * ctx)
{
	memset(ctx, 0, sizeof(aes_context));
}


void aes_ctx_free(aes_context * ctx)
{
	if (ctx->rkeys)
		free(ctx->rkeys);

	aes_ctx_init(ctx);
}


int aes_ctx_set_key(aes_context * ctx,
		             uint8_t * key,
					 int length)
{
    switch(length) {
        case 16: ctx->flavour = AES128; break;
		case 24: ctx->flavour = AES192; break;
		case 32: ctx->flavour = AES256; break;
		default: return AES_TOOL_ERR_INVALID_KEY_LENGTH;
	}

	memcpy(ctx->key, key, length);
    
	ctx->rkeys = malloc(sizeof(uint8_t) * AES_exp_key_length(ctx->flavour));

    key_expansion(ctx->key, ctx->rkeys, ctx->flavour);

	return AES_TOOL_ERR_OK;
}


int aes_ctx_set_iv(aes_context * ctx, uint8_t iv[AES_BLOCK_SIZE])
{
    memcpy(ctx->iv, iv, AES_BLOCK_SIZE);
	return AES_TOOL_ERR_OK;
}
