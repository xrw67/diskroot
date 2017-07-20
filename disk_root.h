#ifndef _DISK_ROOT_H_
#define _DISK_ROOT_H_

#include <stdint.h>
#include "ext4.h"

#define DISKROOT_VERSION "0.1.1"

#define DR_MAGIC "~Disk Root Magic~"
#define DR_MAGIC_SIZE (strlen(DR_MAGIC))

#define DR_CRC32C_INIT 0x20170707

#define DR_BOOT_ZONE 1
#define DR_EXT4_ZONE 2

enum dr_errno_types {
    E_OK = 0,
    E_OTHER,
    E_NO_MEM,
    E_DISK_READ,
    E_DISK_WRITE,
    E_NO_FILE,
    E_BUFFER_TO_SMALL,
    E_ZONE_OUT_RANGE,
    E_MAGIC_NOT_MATCH,
    E_NO_BLOCKS,
    E_OUT_RANGE,
};

// struct dr_err_string {
//     int eno;
//     const char *str;
// };

//const char *dr_strerror(int eno);

struct dr_header { 
    uint32_t zone_type; /* zone type */
    uint64_t f_offset;  /* start block id of file */
    uint32_t f_size;    /* file size */
    uint32_t f_csum;    /* crc32c */
} __attribute__ ((aligned (1)));

#define DR_HEADER_SIZE (sizeof(struct dr_header))

/* Block Device */
struct dr_blkdev {
    char devname[8];
    int dev_fd;
    uint32_t block_size;
    
    int (*open)(struct dr_blkdev *dev);
    void (*close)(struct dr_blkdev *dev);
    int (*bread)(struct dr_blkdev *dev, uint8_t *buf, uint64_t blk_id, uint32_t blk_cnt);
    int (*bwrite)(struct dr_blkdev *dev, uint8_t *buf, uint64_t blk_id, uint32_t blk_cnt);
};

extern struct dr_blkdev sg_blkdev;
extern struct dr_blkdev file_blkdev;

/* mbr */
uint32_t mbr_get_part_offset(struct dr_blkdev *dev, int index);

/* boot zone */
int boot_zone_read_file(struct dr_blkdev *dev, const struct dr_header *hdr,
                        uint8_t *buf, uint32_t buf_size);
int boot_zone_write_file(struct dr_blkdev *dev, const uint8_t *data, uint32_t data_size);

/* ext4 zone */
int ext4_zone_read_file(struct dr_blkdev *dev, const struct dr_header *hdr,
                        uint8_t *buf, uint32_t buf_size);
int ext4_zone_write_file(struct dr_blkdev *dev, const uint8_t *data, uint32_t data_size);

int ext4_zone_delete_file(struct dr_blkdev *dev, struct dr_header *hdr);


int write_dr_header(struct dr_blkdev *dev, struct dr_header *hdr);

#endif /* _DISK_ROOT_H_ */
