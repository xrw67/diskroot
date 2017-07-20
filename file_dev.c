#include "disk_root.h"
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include "utils.h"

static int file_open(struct dr_blkdev *dev)
{
    int fd;
    const char *device_name = "/dev/sda";

    if ((fd = open(device_name, O_RDWR | O_EXCL | O_SYNC)) < 0) {
        log_error("cound not open %s, %s\n", device_name, strerror(errno));
        return -1;
    }

    dev->dev_fd = fd;
    return 0;
}

static void file_close(struct dr_blkdev *dev)
{
    close(dev->dev_fd);
}


static int file_bread(struct dr_blkdev *dev, uint8_t *buf, uint64_t blk_id, uint32_t blk_cnt)
{
    int res;
    uint64_t start;
    uint32_t size, sum = 0;
    
    if (dev->dev_fd < 0)
        return -1;

    start = blk_id * dev->block_size;
    size = blk_cnt * dev->block_size;

    res = lseek(dev->dev_fd, start, SEEK_CUR);
    if (res == -1)
        return -E_DISK_READ;

    while (sum < size) {
        res = read(dev->dev_fd, buf + sum, size - sum);
        if (res < 0)
            return -E_DISK_READ;
        if (res == 0)
            return 0;
        sum += res;
    }
    return 0;
}


static int file_bwrite(struct dr_blkdev *dev, uint8_t *buf, uint64_t blk_id, uint32_t blk_cnt)
{
    int res;
    uint64_t start;
    uint32_t size, sum = 0;
    
    if (dev->dev_fd < 0)
        return -1;

    start = blk_id * dev->block_size;
    size = blk_cnt * dev->block_size;

    res = lseek(dev->dev_fd, start, SEEK_CUR);
    if (res == -1)
        return -E_DISK_WRITE;

    while (sum < size) {
        res = write(dev->dev_fd, buf + sum, size - sum);
        if (res < 0)
            return -E_DISK_WRITE;
        if (res == 0)
            return 0;
        sum += res;
    }
    return 0;    
}

struct dr_blkdev file_blkdev = {
    .devname = "file",
    .block_size = 512,
    .open = file_open,
    .close = file_close,
    .bread = file_bread,
    .bwrite = file_bwrite,
};
