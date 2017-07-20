#include "disk_root.h"
#include <string.h>
#include <stdlib.h>
#include "crc32.h"
#include "utils.h"

static int boot_zone_max_file_size(struct dr_blkdev *dev, uint32_t blk_end)
{
    int rc = 0;
    struct dr_header *hdr;
    uint32_t magic_offset = dev->block_size - DR_MAGIC_SIZE;
    
    uint32_t blk_start = blk_end - 1;

    uint8_t *buf = malloc(dev->block_size);
    if (!buf)
        return -E_NO_MEM;

    /* find boot zone header */
    rc = dev->bread(dev, buf, blk_start, 1);
    if (rc)
        goto out;

    /* match magic */
    if (0 == memcpy(buf + magic_offset, DR_MAGIC, DR_MAGIC_SIZE)) {
        hdr = (struct dr_header *)(buf + magic_offset - DR_HEADER_SIZE);
        
        if (hdr->zone_type == DR_BOOT_ZONE && hdr->f_offset && hdr->f_size) {
            /* skip this sectors */
            blk_start = hdr->f_offset - 1;
        } else {
            blk_start--;
        }
    }

    while (blk_start--) {
        if (dev->bread(dev, buf, blk_start, 1)) {
            free(buf);
            return -E_DISK_READ;
        }
        if (!iszeromem(buf, dev->block_size)) {
            blk_start++;
            break;
        }
    }

    if (blk_end > blk_start)
        rc = (blk_end - blk_start) * dev->block_size - DR_MAGIC_SIZE - DR_HEADER_SIZE;
    
    log_debug("boot zone max file size: %u\n", rc);
out:
    free(buf);
    return rc;
}

int boot_zone_read_file(struct dr_blkdev *dev, const struct dr_header *hdr,
                        uint8_t *buf, uint32_t buf_size)
{
    if (hdr->zone_type != DR_BOOT_ZONE || !hdr->f_offset || !hdr->f_size)
        return -E_NO_FILE;

    if (hdr->f_size > buf_size)
        return -E_BUFFER_TO_SMALL;
    
    uint32_t block_cnt = (hdr->f_size + DR_HEADER_SIZE + DR_MAGIC_SIZE + dev->block_size - 1) / dev->block_size;

    char *blkbuf = malloc(block_cnt * dev->block_size);
    if (!blkbuf)
        return -E_NO_MEM;

    if (dev->bread(dev, blkbuf, hdr->f_offset, block_cnt)) {
        free(blkbuf);
        return -E_DISK_READ;
    }
    
    memcpy(buf, blkbuf, hdr->f_size);
    free(blkbuf);
    return 0;
}

int boot_zone_write_file(struct dr_blkdev *dev, const uint8_t *data, uint32_t data_size)
{
    int ret;
    uint8_t *buf;
    struct dr_header *hdr;
    int block_start, block_end, block_cnt, max_file_size;

    block_end = mbr_get_part_offset(dev, 0);

    if ((int)block_end < 0)
        return (int)block_end;

    block_cnt = (data_size + DR_HEADER_SIZE + DR_MAGIC_SIZE + dev->block_size - 1) / dev->block_size;
    block_start = block_end - block_cnt;

    if ((max_file_size = boot_zone_max_file_size(dev, block_end)) < 0)
        return max_file_size;

    if (max_file_size < data_size + DR_HEADER_SIZE + DR_MAGIC_SIZE)
        return -E_ZONE_OUT_RANGE;

    buf = malloc(block_cnt * dev->block_size);
    if (!buf)
        return -E_NO_MEM;
    
    log_info("data_size=%d, block_cnt=%d, block_start=%d, block_end=%d\n", 
            data_size, block_cnt, block_start, block_end);

    memcpy(buf, data, data_size);
    memset(buf + data_size, 0, block_cnt * dev->block_size - data_size);
    memcpy(buf + (block_cnt * dev->block_size) - DR_MAGIC_SIZE, DR_MAGIC, DR_MAGIC_SIZE);

    /* Set data header */
    hdr = (struct dr_header *)(buf + block_cnt * dev->block_size - DR_MAGIC_SIZE - DR_HEADER_SIZE);
    hdr->zone_type = DR_BOOT_ZONE;
    hdr->f_offset = block_start;
    hdr->f_size = data_size;
    hdr->f_csum = dr_crc32c(DR_CRC32C_INIT, data, data_size);

    ret = -E_DISK_WRITE;
    /* write */
    if (dev->bwrite(dev, buf, block_start, block_cnt))
        goto out;

    /* verify */
    if (dev->bread(dev, buf, block_start, block_cnt)) {
        ret = -E_DISK_READ;
        goto out;
    }

    if (memcmp(buf, data, data_size) != 0)
        goto out;

    ret = 0;
out:
    free(buf);
    return ret;
}

