#ifndef _AES_ENCRYPTION_TOOL_CONST_H_
#define _AES_ENCRYPTION_TOOL_CONST_H_


/*****************************************************************************/
/*                    AES CONSTANT DEFINITIONS                               */


/*  
 *  AES 'flavors' based on each different key length
 */
typedef enum {
	AES128,
	AES192,
	AES256
}AES_t;


/* Word size in bytes*/
#define WORD_SIZE 4

/*  Number of words comprising the state,input and output blocks.
 *  In the standard is called Nb */
#define AES_BLOCK_WORDS   4

/*  AES State, Input & Output block size (bytes) */
#define AES_BLOCK_SIZE (AES_BLOCK_WORDS * WORD_SIZE)

/*  AES Key Lengths (words), in the standard is called Nk */
#define AES128_KEY_WORDS  4
#define AES192_KEY_WORDS  6
#define AES256_KEY_WORDS  8

/*  AES Key Lengths (bytes) */
#define AES128_KEY_LENGTH (AES128_KEY_WORDS * WORD_SIZE)
#define AES192_KEY_LENGTH (AES192_KEY_WORDS * WORD_SIZE)
#define AES256_KEY_LENGTH (AES256_KEY_WORDS * WORD_SIZE)

/*  AES Num of rounds, in the standard is called Nr */
#define AES128_NUM_ROUNDS 10
#define AES192_NUM_ROUNDS 12
#define AES256_NUM_ROUNDS 14

/*  AES Num of round keys */
#define AES128_NUM_ROUND_KEYS ((AES128_NUM_ROUNDS + 1) * AES_BLOCK_WORDS)
#define AES192_NUM_ROUND_KEYS ((AES192_NUM_ROUNDS + 1) * AES_BLOCK_WORDS)
#define AES256_NUM_ROUND_KEYS ((AES256_NUM_ROUNDS + 1) * AES_BLOCK_WORDS)

/*  AES Expanded Key Length (bytes) */
#define AES128_EXP_KEY_LENGTH (AES128_NUM_ROUND_KEYS * WORD_SIZE)
#define AES192_EXP_KEY_LENGTH (AES192_NUM_ROUND_KEYS * WORD_SIZE)
#define AES256_EXP_KEY_LENGTH (AES256_NUM_ROUND_KEYS * WORD_SIZE)


static inline int AES_key_length(AES_t type)
{
    switch(type)
	{
		case AES128: return AES128_KEY_LENGTH;
		case AES192: return AES192_KEY_LENGTH;
		case AES256: return AES256_KEY_LENGTH;
		default: return 0;
	}
}


static inline int AES_num_rounds(AES_t type)
{
	switch(type)
	{
		case AES128: return AES128_NUM_ROUNDS;
		case AES192: return AES192_NUM_ROUNDS;
		case AES256: return AES256_NUM_ROUNDS;
		default: return 0; 
	}
}


static inline int AES_num_round_keys(AES_t type)
{
	switch(type)
	{
		case AES128: return AES128_NUM_ROUND_KEYS;
		case AES192: return AES192_NUM_ROUND_KEYS;
		case AES256: return AES256_NUM_ROUND_KEYS;
		default: return 0;
	}
}


static inline int AES_exp_key_length(AES_t type)
{
	switch(type)
	{
		case AES128: return AES128_EXP_KEY_LENGTH;
		case AES192: return AES192_EXP_KEY_LENGTH;
		case AES256: return AES256_EXP_KEY_LENGTH;
        default: return 0;
	}
}
/*****************************************************************************/


#endif
