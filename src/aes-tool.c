#include "aes_const.h"
#include "aes_cipher.h"
#include "aes_inv_cipher.h"
#include "base_64.h"

#ifdef _linux_
#include <argp.h>
#else
#include "argp.h"
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


#define FILE_MAX_SIZE 4096

int str_len(char * str) {
    int length = 0;
	while(1) {
        if (str[length++] == 0x00)
			break;
	}
	length--;

	return length;
}

/*------------------------------------------------------------------------------------------------------------------------------------------*/
/*        ARGP PART */
const char *argp_program_version = "aes-tool 0.0.0";
const char *argp_program_bug_address = "<dtolosa.93@gmail.com>";
static char text[] = "AES Encryption Tool. Command Line program for encrypting/decrypting files.";
static char doc_text[] = "";

static struct argp_option options[] = { 
    { "encrypt", 'e', 0, 0, "Encrypt given input"},
    { "decrypt", 'd', 0, 0, "Decrypt given input"},
    { "key", 'k', "", 0, "Cipher key. Only admits key lengths of 16, 24 or 32 bytes, corresponding to AES128, AES192 & AES256 standards."},
    { "file", 'f', "", 0, "Input file. Only admits plaint text files with a size no longer that 4KB"},
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
	int length = str_len(arg);
	
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


void read_file(char *arg, struct arguments * arguments)
{
	FILE * fp;
	size_t flen;
	int result;

	fp = fopen(arg, "rb");
    fseek(fp, 0, SEEK_END);
    flen = ftell(fp);
    rewind(fp);

    if (!flen) {
		printf("Error reading file. File is empty!\n");
		exit(1);
	}

    if (flen > FILE_MAX_SIZE) {
	    printf("File too large. Max length allowed is %d bytes\n", FILE_MAX_SIZE);
	    exit(1);
	}

	arguments->input = (uint8_t *)malloc(sizeof(char)*flen);
    //TODO check memory error if malloc fails?

  result = fread (arguments->input, 1, flen, fp);

  if (result != flen) {
      printf("Error reading file.\n");
	  exit (1);
  }

    fclose(fp);
}


static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;
    switch (key) {
    case 'e': {arguments->aes = &AES_cipher; arguments->mode = ENCRYPT;} break;
    case 'd': {arguments->aes = &AES_inv_cipher; arguments->mode = DECRYPT;} break;
    case 'k': parse_key(arg, arguments); break;
    case 'f': read_file(arg, arguments); break;
    case ARGP_KEY_ARG: {arguments->input = (uint8_t *)arg; return 0;}
    default: return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = { options, parse_opt, doc_text, text, 0, 0, 0 };
/*------------------------------------------------------------------------------------------------------------------------------------------*/

#ifdef AES_TOOL_DEBUG
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
#endif

int main(int argc, char * argv[])
{
    struct arguments arguments;

    arguments.aes  = &AES_cipher;
    arguments.mode = AES128;
    arguments.input = NULL;
	arguments.key = NULL;

	/* ARG PARSING */
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    if (!arguments.key) {
		printf("No key is provide!\n");
        argp_help(&argp, stderr, ARGP_HELP_USAGE, "aes-tool");
		exit(1);
	}

	if (!arguments.input) {
		printf("No input is provide!\n");
		argp_help(&argp, stderr, ARGP_HELP_USAGE, "aes-tool");
		exit(1);
	}
#ifdef AES_TOOL_DEBUG
	printf("Options: \n Type: %s | Mode: %s \n Input: %s \n  Key: %s\n",
			arguments.mode?"DECRYPT":"ENCRYPT",
			keylength_to_aes(arguments.keylength),
			arguments.input,
			arguments.key
		  );
#endif
	/* -----------  */

    /*  KEY EXPANSION */
    uint8_t * expandedKey = malloc(sizeof(uint8_t) * AES_exp_key_length(arguments.keylength));
	if (!expandedKey)
		exit(1);

    key_expansion(arguments.key, expandedKey, arguments.keylength);	
    /* -------------- */

	/* PREPARE INPUT */
    size_t inputLen = str_len(arguments.input);
    size_t outputLen = inputLen;

    switch(arguments.mode) {
		case ENCRYPT:
		{
            if (inputLen % AES_BLOCK_SIZE)
		        outputLen += AES_BLOCK_SIZE - (inputLen % AES_BLOCK_SIZE);
		}
		break;
		case DECRYPT:
		{
			//Decode from base64 to binary
            size_t plainLen;
		    char *outputPlain = base64_decode(arguments.input, inputLen, &plainLen);
            arguments.input = outputPlain;
		    inputLen = plainLen;
		    outputLen = plainLen;
		}
		break;
	}

    uint8_t output[outputLen];
	memset(output, 0x00, outputLen);
	memcpy(output, arguments.input, inputLen);
    /* ------------- */

    /* ENCRYPT / DECRYPT */
    int index = 0;
	while(index < outputLen) {
		arguments.aes(&output[index],
				      expandedKey,
					  arguments.keylength);

		index += AES_BLOCK_SIZE;
	}
	/* ----------------- */
    
	/* SHOW OUTPUT */
    switch(arguments.mode) {
	
		case ENCRYPT:
			{
				//encode binary to base64
            	size_t b64len;
                char * output64 = base64_encode(output, outputLen, &b64len); 
	            printf("%s\n", output64);
			}
		break;
		case DECRYPT:
			{
				printf("%s\n", output);
			}
		break;
		default: exit(1);
	}
	/*  ----------- */

}
