#ifndef _HIDE_FILE_UTILS_H_
#define _HIDE_FILE_UTILS_H_

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define log_debug(fmt, ...) \
    printf("[%s:%d DEBUG] " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define log_info(fmt, ...) \
    printf("[%s:%d INFO] " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define log_error(fmt, ...) \
    printf("[%s:%d ERROR] " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)

static inline int iszeromem(const uint8_t *src, int size)
{
    int i = 0;
    while (src[i++] == 0 && i < size) 
    ;
    return (i == size);
}

void hexdump(const char *data, size_t size);
int get_file_size(const char *filename);
int read_file(const char *filename, uint8_t *buf, int *len);
int write_file(const char *filename, uint8_t *buf, int len);

#endif /* _HIDE_FILE_UTILS_H_ */ 
