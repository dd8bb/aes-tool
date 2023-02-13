#include "aes_const.h"
#include "base_64.h"
#include "aes_context.h"
#include "aes_crypt.h"

#ifdef _linux_
#include <argp.h>
#else
#include "argp.h"
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


#define FILE_MAX_SIZE 4096

#define AES_TOOL_ECB_MODE 0
#define AES_TOOL_CBC_MODE 1

/*------------------------------------------------------------------------------------------------------------------------------------------*/
/*        ARGP PART */
const char *argp_program_version = "aes-tool 0.0.0";
const char *argp_program_bug_address = "<dtolosa.93@gmail.com>";
static char text[] = "AES Encryption Tool. Command Line program for encrypting/decrypting files.";
static char doc_text[] = "";

static struct argp_option options[] = {
    { "encrypt", 'e',  0, 0, "Encrypt given input. This is the default option"},
    { "decrypt", 'd',  0, 0, "Decrypt given input"},
    { "key",     'k', "value", 0, "Cipher key. Only admits key lengths of 16, 24 or 32 bytes, corresponding to AES128, AES192 & AES256 standards. Also accepts value to be a file path"},
    { "file",    'f', "path", 0, "Input file. Only admits plain text files with a size no longer that 4KB"},
    { "ivector", 'v', "", 0, "[Optional].Initialization vector for CBC mode. If this option is not indicated a default IV is used." },
    { "ecb",      1,   0, 0, "Use of Electronic CodeBook (ECB) cipher mode."},
	{ "cbc",      2,   0, 0, "Use of Cipher Block Chaining (CBC) cipher mode. This option is set by default." },
	{ "raw",     'r',  0, 0, "Output (encrypt) and Input (decrypt) are not treated as base64 format."},
	{ 0 }
};

struct arguments {
	int operation;
    int mode;
    int raw;
	aes_context ctx;
    size_t inputLen;
    uint8_t * input;
    uint8_t * output;
    int (*crypt) (aes_context *, int, size_t, uint8_t *, uint8_t *);
};


int is_a_file(char *arg) {
    FILE * fp;
	int res = 0;

	fp = fopen(arg, "r");
	if (fp) {
		fclose(fp);
		res++;
	}

	return res;
}


void read_file(char *arg, uint8_t ** data, size_t * length)
{
	FILE * fp;
	size_t flen;
    uint8_t * ptr;
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

	ptr = (uint8_t *)malloc(sizeof(uint8_t)*flen);

    result = fread (ptr, 1, flen, fp);

    if (result != flen) {
        printf("Error reading file.\n");
	    exit (1);
    }

    if (ptr[flen-1] == 0x0A)
		flen--;

    fclose(fp);

    *data = ptr;
	*length = flen;
}

void argp_init(struct arguments * arguments)
{
    arguments->input     = NULL;
    arguments->output    = NULL;
    arguments->raw       = 0;
    arguments->operation = AES_TOOL_ENCRYPT;
    arguments->mode      = AES_TOOL_CBC_MODE;
	arguments->crypt     = &aes_crypt_cbc;
    aes_ctx_init(&arguments->ctx);
}


void parse_key(char *arg, struct arguments * arguments)
{
    uint8_t * key;
	size_t length;
    int err;
    
    if (is_a_file(arg)) {
	    read_file(arg, &key, &length);
	}
	else {
	    key = (uint8_t*)arg;
		length = strlen(arg);
	}

	err = aes_ctx_set_key(&arguments->ctx, key, length);

	if (err == AES_TOOL_ERR_INVALID_KEY_LENGTH) {
	    printf("Key length not valid. Lengths must be of 16, 24 or 32 bytes. Given length: %zu\n", length);
	    exit(1);
	}
}


void parse_vector(char *arg, struct arguments * arguments)
{
	uint8_t * vector;
	size_t length;

	if (is_a_file(arg)) {
		read_file(arg, &vector, &length);
	}
	else {
		vector = (uint8_t*)arg;
		length = strlen(arg);
	}

    if (length != AES_BLOCK_SIZE) {
		printf("Init. Vector size not valid. Length must be 16 bytes.\n");
		exit(1);
	}

	aes_ctx_set_iv(&arguments->ctx, vector);
}


static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;
    switch (key) {
	case  1 : arguments->mode = AES_TOOL_ECB_MODE; arguments->crypt = &aes_crypt_ecb; break;
	case  2 : arguments->mode = AES_TOOL_CBC_MODE; arguments->crypt = &aes_crypt_cbc ; break;
    case 'e': arguments->operation = AES_TOOL_ENCRYPT; break;
    case 'd': arguments->operation = AES_TOOL_DECRYPT; break;
    case 'k': parse_key(arg, arguments); break;
    case 'v': parse_vector(arg, arguments); break;
    case 'f': read_file(arg, &arguments->input, &arguments->inputLen); break;
    case 'r': arguments->raw = 1; break;
    case ARGP_KEY_ARG: 
			  {
				  arguments->inputLen = strlen(arg);
                  arguments->input = (uint8_t *)malloc(sizeof(uint8_t)*arguments->inputLen);
                  memcpy(arguments->input, arg, arguments->inputLen);
				  break;
			  }
    default: return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = { options, parse_opt, doc_text, text, 0, 0, 0 };
/*------------------------------------------------------------------------------------------------------------------------------------------*/

#ifdef AES_TOOL_DEBUG
char * aes_to_str(AES_t type)
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

    argp_init(&arguments);

    
	/* ARG PARSING */
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

	//TODO change key parsing to memeqzero?
    //if (!arguments.key) {
	//	printf("No key is provide!\n");
    //    argp_help(&argp, stderr, ARGP_HELP_USAGE, "aes-tool");
	//	exit(1);
	//}

	if (!arguments.input) {
		printf("No input is provide!\n");
		argp_help(&argp, stderr, ARGP_HELP_USAGE, "aes-tool");
		exit(1);
	}
#ifdef AES_TOOL_DEBUG
	printf("Options: \n Operation: %s | Flavour: %s | Mode: %s \n Input: %s \n  Key: %s\n",
			arguments.operation?"DECRYPT":"ENCRYPT",
			aes_to_str(arguments.ctx.flavour),
			arguments.mode?"CBC":"ECB",
			arguments.input,
			arguments.ctx.key
		  );
#endif
	/* -----------  */

    
	/* PREPARE INPUT */

    switch(arguments.operation) {
		case AES_TOOL_ENCRYPT:
		{
			size_t prevLen = arguments.inputLen;

            if (arguments.inputLen % AES_BLOCK_SIZE) {
		        arguments.inputLen += AES_BLOCK_SIZE - (arguments.inputLen % AES_BLOCK_SIZE);
                arguments.input = (uint8_t *) realloc(arguments.input, arguments.inputLen);
                memset(&arguments.input[prevLen], 0, arguments.inputLen - prevLen); //Zero padding
			}
		}
		break;
		case AES_TOOL_DECRYPT:
		{
			//Decode from base64 to binary
		    if(!arguments.raw) {	
                size_t plainLen;
		        uint8_t *outputPlain = base64_decode((const char *)arguments.input, arguments.inputLen, &plainLen);
                arguments.input = outputPlain;
		        arguments.inputLen = plainLen;
			}
		}
		break;
	}

    arguments.output = (uint8_t *)malloc(sizeof(uint8_t)*arguments.inputLen); 
    //uint8_t output[arguments.inputLen];
    /* ------------- */

    /* ENCRYPT / DECRYPT */
    int error;
	error = arguments.crypt(&arguments.ctx, arguments.operation, arguments.inputLen, arguments.input, arguments.output);
	/* ----------------- */

	/* SHOW OUTPUT */
    switch(arguments.operation) {

		case AES_TOOL_ENCRYPT:
			{
				//encode binary to base64
            	if (!arguments.raw) {
				    size_t b64len;
                    char * output64 = base64_encode(arguments.output, arguments.inputLen, &b64len);
	                printf("%s\n", output64);
				}
				else {
					printf("%s\n", arguments.output);
				}
			}
		break;
		case AES_TOOL_DECRYPT:
			{
				//need to iterate over output since print as a string could be wrong due to the presence of zeroes
				if (!arguments.raw) {
				    printf("%s\n", arguments.output);
				}
				else {
				    for (int i=0; i < arguments.inputLen; i++)
					    printf("%c", arguments.output[i]);
				}
			}
		break;
		default: exit(1);
	}
	/*  ----------- */

}
