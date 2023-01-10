#ifndef _AES_ENCRYPTION_TOOL_CYPHER_H_
#define _AES_ENCRYPTION_TOOL_CYPHER_H_


#include "aes_const.h"
#include "aes_core.h"

#include <string.h>

void AES_cipher(uint8_t * block, uint8_t * expandedKey, AES_t type)
{
	int numRounds = AES_num_rounds(type);
	uint8_t state[AES_BLOCK_SIZE];

	memcpy(state, block, AES_BLOCK_SIZE);

	add_round_key(state, expandedKey);

	for (int i = 0; i < numRounds - 1; i++)
	{
		sub_bytes(state);
		shift_rows(state);
		mix_columns(state);
		add_round_key(state, &expandedKey[(i+1) * AES_BLOCK_SIZE]);
	}

	sub_bytes(state);
	shift_rows(state);
	add_round_key(state, &expandedKey[numRounds * AES_BLOCK_SIZE]);

	memcpy(block, state, AES_BLOCK_SIZE);
}


#endif
