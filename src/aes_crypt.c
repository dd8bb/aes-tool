#include "aes_crypt.h"
#include "aes_const.h"
#include "aes_cipher.h"
#include "aes_inv_cipher.h"

#include <string.h>


static int vector_not_initialized(const uint8_t iv[AES_BLOCK_SIZE])
{
	for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        if (iv[i])
			return 0;
	}

	return 1;
}


int aes_crypt_ecb(aes_context * ctx, int mode, size_t inputLen, uint8_t * input, uint8_t * output)
{
    int index = 0;
    void (*aes) (uint8_t *, uint8_t *, AES_t);
	
	if (inputLen % 16)
		return AES_TOOL_ERR_INVALID_INPUT_LENGTH;

    if (mode == AES_TOOL_ENCRYPT)
	   aes = &AES_cipher;
    else
	   aes = &AES_inv_cipher;	

    memcpy(output, input, inputLen);

	while (index < inputLen) {
		aes(&output[index],
			ctx->rkeys,
			ctx->flavour);

		index += AES_BLOCK_SIZE;
	}

	return AES_TOOL_ERR_OK;
}


int aes_crypt_cbc(aes_context * ctx, int mode, size_t inputLen, uint8_t * input, uint8_t * output)
{
	int index = 0;

	if (inputLen % 16)
		return AES_TOOL_ERR_INVALID_INPUT_LENGTH;

	if (vector_not_initialized(ctx->iv)) 
	    aes_ctx_set_iv(ctx, AES_TOOL_DEFAULT_IV); // Set default I.V.
	
	memcpy(output, input, inputLen);

	if (mode == AES_TOOL_ENCRYPT) {

        while (index < inputLen) {

			for (int i=0; i < AES_BLOCK_SIZE; i++)
				output[i + index] = input[i + index] ^ ctx->iv[i];

			    AES_cipher(&output[index],
						   ctx->rkeys,
						   ctx->flavour);

				memcpy(ctx->iv, &output[index], AES_BLOCK_SIZE);

				index += AES_BLOCK_SIZE;
		}
    }
	else {

		while (index < inputLen) {

			AES_inv_cipher(&output[index],
					       ctx->rkeys,
						   ctx->flavour);

			for (int i = 0; i < AES_BLOCK_SIZE; i++)
				output[i + index] ^= ctx->iv[i];

			memcpy(ctx->iv, &input[index], AES_BLOCK_SIZE);

            index += AES_BLOCK_SIZE;
		}
	}

    return AES_TOOL_ERR_OK;
}


