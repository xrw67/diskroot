#include "utils.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

void hexdump(const char *data, size_t size)
{
    static char *b2h = "0123456789abcdef";
    int i, j, pos, linesize;
    unsigned char line[48 + 16 + 1];
    char c;

    for (i = 0; i < size; i += 16) {
        if (size - i < 16)
            linesize = size - i;
        else
            linesize = 16;

        memset(line, ' ', sizeof(line));
        pos = 0;

        for (j = 0; j < 16; j++) {
            c = data[i+j];

            if (j < linesize) {
                line[pos] = b2h[(c & 0xf0) >> 4];
                line[pos+1] = b2h[c & 0x0f];
            }

            pos += 3;
        }

        for (j = 0; j < linesize; j++) {
            c = data[i+j];

            if (c >= 0x20 && c <= 0x7e)
                line[pos++] = c;
            else
                line[pos++] = '.';
        }

        line[pos] = '\0';

        printf("%04x: %s\n", i, line);
    }
}

int get_file_size(const char *filename)
{
    struct stat st;
    if (stat(filename, &st) == 0)
        return st.st_size;
    return 0;
}

int read_file(const char *filename, uint8_t *buf, int *len)
{
    int fd, pos = 0, read_bytes;

    if ((fd = open(filename, O_RDONLY)) < 0)
        return fd;

    while (pos < *len) {
        read_bytes = read(fd, buf + pos, *len - pos);
        if (read_bytes < 0) {
            close(fd);
            return read_bytes;
        }
        if (read_bytes == 0)
            break;
        pos += read_bytes;
    }

    close(fd);
    *len = pos;
    return 0;
}

int write_file(const char *filename, uint8_t *buf, int len)
{
    int fd, pos= 0, write_bytes;

    if ((fd = open(filename, O_WRONLY | O_TRUNC | O_CREAT | O_SYNC, S_IRWXU)) < 0)
        return fd;

    while (pos < len) {
        write_bytes = write(fd, buf + pos, len - pos);
        if (write_bytes < 0) {
            close(fd);
            return write_bytes;
        }
        
        if (write_bytes == 0)
            break;
        pos += write_bytes;
    }

    close(fd);
    return 0;
}

