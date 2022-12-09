#include "aes_const.h"
#include "aes_cipher.h"
#include "aes_inv_cipher.h"

#ifdef _linux_
#include <argp.h>
#else
#include "argp.h"
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>



const char *argp_program_version = "aes-tool 0.0.0";
const char *argp_program_bug_address = "<dtolosa.93@gmail.com>";
static char text[] = "AES Encryption Tool. Command Line program for encrypting/decrypting files.";
static char doc_text[] = "";

static struct argp_option options[] = { 
    { "encrypt", 'e', 0, 0, "Encrypt given input"},
    { "decrypt", 'd', 0, 0, "Decrypt given input"},
    { "key", 'k', "", 0, "Cipher key. Only admits key lengths of 16, 24 or 32 bytes, corresponding to AES128, AES192 & AES256 standards."},
    { 0 } 
};

struct arguments {
	enum {ENCRYPT, DECRYPT} mode;
	AES_t keylength;
    uint8_t * key;
    uint8_t * input;
	void (*aes) (uint8_t *, uint8_t *, AES_t);
};


void parse_key(char *arg, struct arguments * arguments)
{
	int length = 0;
	while (1) {
        printf("%c", arg[length]);
		if (arg[length++] == 0x00) 
				break;
	}
    length--;

	switch(length) {
		case 16:
			{
			    arguments->keylength = AES128;
                arguments->key = (uint8_t *)malloc(length);
				memcpy(arguments->key, arg, length);
			}
		break;
		case 24:
		    {
		        arguments->keylength = AES192;
                arguments->key = (uint8_t *)malloc(length);
				memcpy(arguments->key, arg, length);
			}
		break;
		case 32:
            {
		        arguments->keylength = AES256;
                arguments->key = (uint8_t *)malloc(length);
				memcpy(arguments->key, arg, length);
			}
		break;
		default:
		    {
				printf("Key length not valid. Lengths must be of 16, 24 or 32 bytes. Given length: %d\n", length);
				exit(1);
			}

	}
}


static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;
    switch (key) {
    case 'e': {arguments->aes = &AES_cipher; arguments->mode = ENCRYPT;} break;
    case 'd': {arguments->aes = &AES_inv_cipher; arguments->mode = DECRYPT;} break;
    case 'k': parse_key(arg, arguments); break;
    case ARGP_KEY_ARG: {arguments->input = arg; return 0;}
    default: return ARGP_ERR_UNKNOWN;
    }
    return 0;
}


char * keylength_to_aes(AES_t type)
{
	switch(type)
	{
		case AES128: return "AES128";
		case AES192: return "AES192";
		case AES256: return "AES256";
		default: return "";
	}
}


static struct argp argp = { options, parse_opt, doc_text, text, 0, 0, 0 };


int main(int argc, char * argv[])
{
    struct arguments arguments;

    arguments.aes  = &AES_cipher;
    arguments.mode = AES128;
    arguments.input = NULL;
	arguments.key = NULL;

    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    if (!arguments.key) {
		printf("No key is provide!\n");
		exit(1);
	}

	if (!arguments.input) {
		printf("No input is provide!\n");
		exit(1);
	}

	printf("Options: \n Type: %s | Mode: %s \n Input: %s \n | Key: %s\n",
			arguments.mode?"DECRYPT":"ENCRYPT",
			keylength_to_aes(arguments.keylength),
			arguments.input,
			arguments.key
		  );
}
