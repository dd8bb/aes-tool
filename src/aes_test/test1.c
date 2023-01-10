#include "../aes_cipher.h"
#include "../aes_inv_cipher.h"
#include "../lookup_tables.h"
#include "../aes_const.h"

#include <stdio.h>
#include <stdlib.h>

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


void cipher_check(const uint8_t * result, const uint8_t * table)
{
	for (int i=0; i < AES_BLOCK_WORDS; i++)
	{
		for (int j=0; j < WORD_SIZE; j++)
		{
			if (result[(i*WORD_SIZE)+j] != table[(i*WORD_SIZE)+j]) {
                uint32_t * resultWord = (uint32_t *)&result[i*WORD_SIZE];
			    uint32_t * testWord = (uint32_t *)&table[i*WORD_SIZE];
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

}


void show_block(const uint8_t * block)
{
    for (int i=0; i < AES_BLOCK_WORDS; i++)
	{
		uint32_t * word = (uint32_t *)&block[i*WORD_SIZE];
		printf("Word: %d | Value: %4X\n",
				i,
				is_big_endian()?*word:swap_word(word)
			  );
	}
}


int main(int argc, char * argv[])
{
	uint8_t block[AES_BLOCK_SIZE];
    uint8_t expanded_key[AES128_EXP_KEY_LENGTH];

    memcpy(block, t1_input, AES_BLOCK_SIZE);
    
	key_expansion(t0_cipher_key_128, expanded_key, AES128);

    printf("Init AES128 Encryption TEST\n");

	printf("Block: \n");
	show_block(block);

	printf("Encrypting block...\n");
    AES_cipher(block, expanded_key, AES128);
    cipher_check(block, t1_output);
	if (error_flag) {
		printf("Something went wrong...\n");
        exit(1);
	}
	else
		printf("Done!\n");

    printf("Encrypted block: \n");
	show_block(block);

    printf("Decrypting block...\n");
    AES_inv_cipher(block, expanded_key, AES128);
    cipher_check(block, t1_input);	
    if (error_flag) {
		printf("Something went wrong...\n");
        exit(1);
	}
	else
		printf("Done!\n");

	printf("Decrypted block: \n");
	show_block(block);
}
