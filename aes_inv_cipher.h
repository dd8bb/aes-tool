#ifndef _AES_ENCRYPTION_TOOL_INVERSE_CYPHER_H_
#define _AES_ENCRYPTION_TOOL_INVERSE_CYPHER_H_


#include "aes_const.h"
#include "aes_core.h"


void AES_inv_cipher(uint8_t * block, uint8_t * expandedKey, AES_t type)
{
	int numRounds = AES_num_rounds(type);
	uint8_t state[AES_BLOCK_SIZE];

	memcpy(state, block, AES_BLOCK_SIZE);

	add_round_key(state, &expandedKey[numRounds * AES_BLOCK_SIZE]);

	for (int i = numRounds - 1; i > 0; i--)
	{
		inv_shift_rows(state);
		inv_sub_bytes(state);
		add_round_key(state, &expandedKey[i * AES_BLOCK_SIZE]);
		inv_mix_columns(state);
	}

	inv_shift_rows(state);
	inv_sub_bytes(state);
	add_round_key(state, expandedKey);

	memcpy(block, state, AES_BLOCK_SIZE);
}


#endif
