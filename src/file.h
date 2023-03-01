#ifndef AES_TOOL_FILE_H_
#define AES_TOOL_FILE_H_

#define FILE_MAX_SIZE 4096


typedef enum {
    FILE_ERR_OK,
    FILE_ERR_OPEN,
    FILE_ERR_READ,
    FILE_ERR_WRITE,
    FILE_ERR_EMPTY,
    FILE_ERR_OVERSIZED,
}file_error_t;
/*
 * @brief: Check if given string is a valid filepath to a file
 */
int filepath_is_valid(char *str);

/*
 * @brief: Open file in read mode and allocate its content, it can be retrieved through *data
 */
int read_file(char *fpath,  uint8_t ** data, size_t * length);


/*
 * @brief: Writes length bytes from data buffer into a file located at fpath
 */
int write_file(char *fpath, uint8_t * data, size_t * length);

#endif
