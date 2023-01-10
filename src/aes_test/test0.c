#include "../aes_const.h"
#include "../aes_core.h"
#include "../lookup_tables.h"

#include <stdio.h>
#include <stdlib.h>

/*    AES KEY EXPANSION TEST
 *   This program tests the key schedule algorithm for each key size (128, 192, 256).
 *   Values of each input cipher key and output expanded key
 *   are taken from the standard's examples. (FIPS-197 Appendix A).
 */

int error_flag = 0;


int is_big_endian(void)
{
	return (*(uint16_t*)"\0\xff" < 0x100);
}


uint32_t swap_word(uint32_t * word)
{
	uint32_t result = *word;

	return ((result & 0xff)       << 24  |
			(result & 0xff00)     << 8   |
			(result & 0xff0000)   >> 8   |
			(result & 0xff000000) >> 24);
}


void prepare_expand_key_test(AES_t type, uint8_t ** cipher, uint8_t ** expanded, uint8_t ** result)
{
	switch(type)
	{
		case AES128:
			*cipher   = (uint8_t *)t0_cipher_key_128;
			*expanded = (uint8_t *)t0_expanded_key_128;
			*result   = (uint8_t *)malloc(AES128_EXP_KEY_LENGTH);
	    break;
		case AES192:
		    *cipher   = (uint8_t *)t0_cipher_key_192;
			*expanded = (uint8_t *)t0_expanded_key_192;
			*result   = (uint8_t *)malloc(AES192_EXP_KEY_LENGTH);
		break;
		case AES256:
		    *cipher   = (uint8_t *)t0_cipher_key_256;
			*expanded = (uint8_t *)t0_expanded_key_256;
			*result   = (uint8_t *)malloc(AES256_EXP_KEY_LENGTH);
        break;
		default: break;
	}
}


void test_expand_key(AES_t type)
{
	uint8_t * cipher_key = NULL, * expanded_key = NULL, * result = NULL;
    
	prepare_expand_key_test(type, &cipher_key, &expanded_key, &result);
    
	if (!cipher_key || !expanded_key || !result) {
	    error_flag++;
		return;
	}

    key_expansion(cipher_key, result, type);

    int totalWords = AES_num_round_keys(type);
	for (int i=0; i < totalWords; i++)
	{
		for (int j=0; j < WORD_SIZE; j++)
		{
			if (result[(i*WORD_SIZE)+j] != expanded_key[(i*WORD_SIZE)+j]) {
                uint32_t * resultWord = (uint32_t *)&result[i*WORD_SIZE];
			    uint32_t * testWord = (uint32_t *)&expanded_key[i*WORD_SIZE];
                printf(" Error. @Word: %d | Expected Value: %4X | Got: %4X\n",
						i,
					   	is_big_endian()?*testWord:swap_word(testWord),
					    is_big_endian()?*resultWord:swap_word(resultWord)
					  );
				error_flag++;
                break;
			}
		}
	}
    free(result);
}


int main(int argc, char *argv[])
{
    printf("Testing Key Expansion Algorithm...\n\n");

    printf("Testing for AES128 Key Length...\n");
	test_expand_key(AES128);
	if (error_flag) 
        printf("Seems something gone wrong...Total wrong words: %d\n\n", error_flag);
	else
        printf("Done!\n\n");

    printf("Testing for AES192 Key Length...\n");
	error_flag = 0;
	test_expand_key(AES192);
	if (error_flag) 
        printf("Seems something gone wrong...Total wrong words: %d\n\n", error_flag);
	else
        printf("Done!\n\n");

    printf("Testing for AES256 Key Length...\n");
	error_flag = 0;
	test_expand_key(AES256);
	if (error_flag) 
        printf("Seems something gone wrong...Total wrong words: %d\n\n", error_flag);
	else
        printf("Done!\n\n");

}
