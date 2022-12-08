#include "aes_core.h"

#include "lookup_tables.h"

#include <string.h>



static inline int is_big_endian(void)
{
	return (*(uint16_t*)"\0\xff" < 0x100);
}


static inline void sub_word(uint8_t word[WORD_SIZE])
{
    for (int i = 0; i < WORD_SIZE; i++)
		word[i] = s_box[word[i]];
}


static inline void rot_word(uint8_t word[WORD_SIZE])
{
	uint32_t * w = (uint32_t *)word;

    //Bit shift depends on how system treats word (uint32_t)
	//In big endian system it's done from most-significant byte to least-significant
	//In little endian it's done from least-significant byte to most-significant
    if (is_big_endian())
        *w = (*w << 8 | ((*w & 0xFF000000) >> 24));
    else
		*w = (*w >> 8 | ((*w & 0xFF) << 24));
}


static void complex_func(uint8_t word[WORD_SIZE], int rconIndex)
{
	// Word left shift by 1 byte
    rot_word(word);	

	// Word substitution
    sub_word(word);

    // Word XORed with Rcon
	word[0] ^= rcon[rconIndex];
}


void key_expansion(uint8_t * key, uint8_t * expandedKey, AES_t type)
{
    int keyLength = AES_key_length(type);
    int expKeyLength = AES_exp_key_length(type); 
	int generatedBytes = 0; 

	//First bytes of expanded keys are the master key bytes
    memcpy(expandedKey, key, keyLength);
    generatedBytes += keyLength;

    int rconIndex=1;
	uint8_t prevWord[WORD_SIZE];
	while (generatedBytes < expKeyLength)
	{
		memcpy(prevWord, &expandedKey[generatedBytes - WORD_SIZE], WORD_SIZE);
        
	    if ((generatedBytes % keyLength) == 0)
		    complex_func(prevWord, rconIndex++);
		else if ((type == AES256) && ((generatedBytes % keyLength) == 16))
		    sub_word(prevWord);

		for (int i = 0; i < WORD_SIZE; i++) {
			expandedKey[generatedBytes] = expandedKey[generatedBytes - keyLength] ^ prevWord[i];
		    generatedBytes++;
		}
	}
	
}


void add_round_key(uint8_t state[AES_BLOCK_SIZE], uint8_t roundKey[AES_BLOCK_SIZE])
{
	for (int i = 0; i < AES_BLOCK_SIZE; i++)
		state[i] ^= roundKey[i];
}


void sub_bytes(uint8_t state[AES_BLOCK_SIZE])
{
	for (int i = 0; i < AES_BLOCK_SIZE; i++)
		state[i] = s_box[state[i]];
}


void inv_sub_bytes(uint8_t state[AES_BLOCK_SIZE])
{
	for (int i = 0; i < AES_BLOCK_SIZE; i++)
		state[i] = inv_s_box[state[i]];
}


void shift_rows(uint8_t state[AES_BLOCK_SIZE])
{
    uint8_t temp[AES_BLOCK_SIZE];

	//First row
	temp[0]  = state[0];
	temp[4]  = state[4];
	temp[8]  = state[8];
	temp[12] = state[12];

	//Second row
	temp[1]  = state[5];
	temp[5]  = state[9];
	temp[9]  = state[13];
	temp[13] = state[1];

	//Third row
	temp[2]  = state[10];
	temp[6]  = state[14];
	temp[10] = state[2];
	temp[14] = state[6];

	//Fourth row
	temp[3]  = state[15];
	temp[7]  = state[3];
	temp[11] = state[7];
	temp[15] = state[11];

	memcpy(state, temp, AES_BLOCK_SIZE);
}


void inv_shift_rows(uint8_t state[AES_BLOCK_SIZE])
{
	uint8_t temp[AES_BLOCK_SIZE];

	//First row
	temp[0]  = state[0];
	temp[4]  = state[4];
    temp[8]  = state[8];
	temp[12] = state[12];

	//Second row
	temp[1]  = state[13];
	temp[5]  = state[1];
	temp[9]  = state[5];
	temp[13] = state[9];

	//Third row
	temp[2]  = state[10];
	temp[6]  = state[14];
	temp[10] = state[2];
	temp[14] = state[6];

	//Fourth row
	temp[3]  = state[7];
	temp[7]  = state[11];
	temp[11] = state[15];
	temp[15] = state[3];

	memcpy(state, temp, AES_BLOCK_SIZE);
}


void mix_columns(uint8_t state[AES_BLOCK_SIZE])
{
    uint8_t temp[AES_BLOCK_SIZE];

	//First column
	temp[0] = mul_2[state[0]] ^ mul_3[state[1]] ^ state[2] ^ state[3]; 
	temp[1] = state[0] ^ mul_2[state[1]] ^ mul_3[state[2]] ^ state[3];
	temp[2] = state[0] ^ state[1] ^ mul_2[state[2]] ^ mul_3[state[3]]; 
	temp[3] = mul_3[state[0]] ^ state[1] ^ state[2] ^ mul_2[state[3]];

	//Second column
	temp[4] = mul_2[state[4]] ^ mul_3[state[5]] ^ state[6] ^ state[7];
    temp[5] = state[4] ^ mul_2[state[5]] ^ mul_3[state[6]] ^ state[7];
	temp[6] = state[4] ^ state[5] ^ mul_2[state[6]] ^ mul_3[state[7]]; 
	temp[7] = mul_3[state[4]] ^ state[5] ^ state[6] ^ mul_2[state[7]];

    //Third column
	temp[8]  = mul_2[state[8]] ^ mul_3[state[9]] ^ state[10] ^ state[11];
    temp[9]  = state[8] ^ mul_2[state[9]] ^ mul_3[state[10]] ^ state[11];
	temp[10] = state[8] ^ state[9] ^ mul_2[state[10]] ^ mul_3[state[11]]; 
	temp[11] = mul_3[state[8]] ^ state[9] ^ state[10] ^ mul_2[state[11]];

    //Fourth column
	temp[12] = mul_2[state[12]] ^ mul_3[state[13]] ^ state[14] ^ state[15];
    temp[13] = state[12] ^ mul_2[state[13]] ^ mul_3[state[14]] ^ state[15];
	temp[14] = state[12] ^ state[13] ^ mul_2[state[14]] ^ mul_3[state[15]]; 
	temp[15] = mul_3[state[12]] ^ state[13] ^ state[14] ^ mul_2[state[15]];

    memcpy(state, temp, AES_BLOCK_SIZE);
}


void inv_mix_columns(uint8_t state[AES_BLOCK_SIZE])
{
	uint8_t temp[AES_BLOCK_SIZE];

	//First column
	temp[0] = mul_14[state[0]] ^ mul_11[state[1]] ^ mul_13[state[2]] ^ mul_9[state[3]];
	temp[1] = mul_9[state[0]] ^ mul_14[state[1]] ^ mul_11[state[2]] ^ mul_13[state[3]];
	temp[2] = mul_13[state[0]] ^ mul_9[state[1]] ^ mul_14[state[2]] ^ mul_11[state[3]];
	temp[3] = mul_11[state[0]] ^ mul_13[state[1]] ^ mul_9[state[2]] ^ mul_14[state[3]];

    //Second column
	temp[4] = mul_14[state[4]] ^ mul_11[state[5]] ^ mul_13[state[6]] ^ mul_9[state[7]];
	temp[5] = mul_9[state[4]] ^ mul_14[state[5]] ^ mul_11[state[6]] ^ mul_13[state[7]];
	temp[6] = mul_13[state[4]] ^ mul_9[state[5]] ^ mul_14[state[6]] ^ mul_11[state[7]];
	temp[7] = mul_11[state[4]] ^ mul_13[state[5]] ^ mul_9[state[6]] ^ mul_14[state[7]];

    //Third column
	temp[8]  = mul_14[state[8]] ^ mul_11[state[9]] ^ mul_13[state[10]] ^ mul_9[state[11]];
	temp[9]  = mul_9[state[8]] ^ mul_14[state[9]] ^ mul_11[state[10]] ^ mul_13[state[11]];
	temp[10] = mul_13[state[8]] ^ mul_9[state[9]] ^ mul_14[state[10]] ^ mul_11[state[11]];
	temp[11] = mul_11[state[8]] ^ mul_13[state[9]] ^ mul_9[state[10]] ^ mul_14[state[11]];

    //First column
	temp[12] = mul_14[state[12]] ^ mul_11[state[13]] ^ mul_13[state[14]] ^ mul_9[state[15]];
	temp[13] = mul_9[state[12]] ^ mul_14[state[13]] ^ mul_11[state[14]] ^ mul_13[state[15]];
	temp[14] = mul_13[state[12]] ^ mul_9[state[13]] ^ mul_14[state[14]] ^ mul_11[state[15]];
	temp[15] = mul_11[state[12]] ^ mul_13[state[13]] ^ mul_9[state[14]] ^ mul_14[state[15]];

    memcpy(state, temp, AES_BLOCK_SIZE);
}
