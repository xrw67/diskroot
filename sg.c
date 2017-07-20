#include "disk_root.h"
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/major.h>
#include "sg_io_linux.h"
#include "utils.h"

#define MAX_SCSI_CDBSZ 16
#define DEF_TIMEOUT 5000       /* 5 seconds */
#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */

static int sg_build_scsi_cdb(unsigned char *cdbp, int cdb_sz,
                             unsigned int blocks, long long start_block,
                             int write_true, int fua, int dpo)
{
    int rd_opcode[] = {0x8, 0x28, 0xa8, 0x88};
    int wr_opcode[] = {0xa, 0x2a, 0xaa, 0x8a};
    int sz_ind;

    memset(cdbp, 0, cdb_sz);
    if (dpo)
        cdbp[1] |= 0x10;
    if (fua)
        cdbp[1] |= 0x8;
    switch (cdb_sz) {
    case 6:
        sz_ind = 0;
        cdbp[0] = (unsigned char)(write_true ? wr_opcode[sz_ind] :
                                               rd_opcode[sz_ind]);
        cdbp[1] = (unsigned char)((start_block >> 16) & 0x1f);
        cdbp[2] = (unsigned char)((start_block >> 8) & 0xff);
        cdbp[3] = (unsigned char)(start_block & 0xff);
        cdbp[4] = (256 == blocks) ? 0 : (unsigned char)blocks;
        if (blocks > 256) {
            log_error("for 6 byte commands, maximum number of "
                            "blocks is 256\n");
            return 1;
        }
        if ((start_block + blocks - 1) & (~0x1fffff)) {
            log_error("for 6 byte commands, can't address blocks"
                            " beyond %d\n", 0x1fffff);
            return 1;
        }
        if (dpo || fua) {
            log_error("for 6 byte commands, neither dpo nor fua"
                            " bits supported\n");
            return 1;
        }
        break;
    case 10:
        sz_ind = 1;
        cdbp[0] = (unsigned char)(write_true ? wr_opcode[sz_ind] :
                                               rd_opcode[sz_ind]);
        cdbp[2] = (unsigned char)((start_block >> 24) & 0xff);
        cdbp[3] = (unsigned char)((start_block >> 16) & 0xff);
        cdbp[4] = (unsigned char)((start_block >> 8) & 0xff);
        cdbp[5] = (unsigned char)(start_block & 0xff);
        cdbp[7] = (unsigned char)((blocks >> 8) & 0xff);
        cdbp[8] = (unsigned char)(blocks & 0xff);
        if (blocks & (~0xffff)) {
            log_error("for 10 byte commands, maximum number of "
                            "blocks is %d\n", 0xffff);
            return 1;
        }
        break;
    case 12:
        sz_ind = 2;
        cdbp[0] = (unsigned char)(write_true ? wr_opcode[sz_ind] :
                                               rd_opcode[sz_ind]);
        cdbp[2] = (unsigned char)((start_block >> 24) & 0xff);
        cdbp[3] = (unsigned char)((start_block >> 16) & 0xff);
        cdbp[4] = (unsigned char)((start_block >> 8) & 0xff);
        cdbp[5] = (unsigned char)(start_block & 0xff);
        cdbp[6] = (unsigned char)((blocks >> 24) & 0xff);
        cdbp[7] = (unsigned char)((blocks >> 16) & 0xff);
        cdbp[8] = (unsigned char)((blocks >> 8) & 0xff);
        cdbp[9] = (unsigned char)(blocks & 0xff);
        break;
    case 16:
        sz_ind = 3;
        cdbp[0] = (unsigned char)(write_true ? wr_opcode[sz_ind] :
                                               rd_opcode[sz_ind]);
        cdbp[2] = (unsigned char)((start_block >> 56) & 0xff);
        cdbp[3] = (unsigned char)((start_block >> 48) & 0xff);
        cdbp[4] = (unsigned char)((start_block >> 40) & 0xff);
        cdbp[5] = (unsigned char)((start_block >> 32) & 0xff);
        cdbp[6] = (unsigned char)((start_block >> 24) & 0xff);
        cdbp[7] = (unsigned char)((start_block >> 16) & 0xff);
        cdbp[8] = (unsigned char)((start_block >> 8) & 0xff);
        cdbp[9] = (unsigned char)(start_block & 0xff);
        cdbp[10] = (unsigned char)((blocks >> 24) & 0xff);
        cdbp[11] = (unsigned char)((blocks >> 16) & 0xff);
        cdbp[12] = (unsigned char)((blocks >> 8) & 0xff);
        cdbp[13] = (unsigned char)(blocks & 0xff);
        break;
    default:
        log_error("expected cdb size of 6, 10, 12, or 16 but got"
                        " %d\n", cdb_sz);
        return 1;
    }
    return 0;
}

/* -1 -> unrecoverable error, 0 -> successful, 1 -> recoverable (ENOMEM),
   2 -> try again */
static int sg_read(int sg_fd, unsigned char *buff, int blocks,
                       long long from_block, int bs, int cdbsz, int fua,
                       int dpo)
{
    int k, res;
    unsigned char rdCmd[MAX_SCSI_CDBSZ];
    unsigned char senseBuff[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;

    if (sg_build_scsi_cdb(rdCmd, cdbsz, blocks, from_block, 0, fua, dpo)) {
        log_error("bad rd cdb build, from_block=%lld, blocks=%d\n",
                from_block, blocks);
        return -1;
    }

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = cdbsz;
    io_hdr.cmdp = rdCmd;
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = bs * blocks;
    io_hdr.dxferp = buff;
    io_hdr.mx_sb_len = SENSE_BUFF_LEN;
    io_hdr.sbp = senseBuff;
    io_hdr.timeout = DEF_TIMEOUT;
    io_hdr.pack_id = (int)from_block;

    // log_info("    read cdb: ");
    // for (k = 0; k < cdbsz; ++k)
    //     fprintf(stderr, "%02x ", rdCmd[k]);
    // fprintf(stderr, "\n");
  

    while (((res = ioctl(sg_fd, SG_IO, &io_hdr)) < 0) && (EINTR == errno))
        ;
    if (res < 0) {
        if (ENOMEM == errno)
            return 1;
        log_error("reading (SG_IO) on sg device, error: %s", strerror(errno));
        return -1;
    }

    // log_info("      duration=%u ms\n", io_hdr.duration);
    switch (sg_err_category3(&io_hdr)) {
    case SG_LIB_CAT_CLEAN:
        break;
    case SG_LIB_CAT_RECOVERED:
        sg_chk_n_print3("reading, continue", &io_hdr, 1);
        break;
    default:
        sg_chk_n_print3("reading", &io_hdr, 1);
        return -1;
    }
    return 0;
}


/* 0 -> successful, -1 -> unrecoverable error, -2 -> recoverable (ENOMEM),
   -3 -> try again (media changed unit attention) */
static int sg_write(int sg_fd, unsigned char * buff, int blocks,
                    long long to_block, int bs, int cdbsz, int fua,
                    int dpo)
{
    unsigned char wrCmd[MAX_SCSI_CDBSZ];
    unsigned char senseBuff[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;
    int res, k, info_valid;
    unsigned long long io_addr = 0;

    if (sg_build_scsi_cdb(wrCmd, cdbsz, blocks, to_block, 1, fua, dpo)) {
        log_error("bad wr cdb build, to_block=%lld, blocks=%d\n",
                to_block, blocks);
        return -1;
    }

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = cdbsz;
    io_hdr.cmdp = wrCmd;
    io_hdr.dxfer_direction = SG_DXFER_TO_DEV;
    io_hdr.dxfer_len = bs * blocks;
    io_hdr.dxferp = buff;
    io_hdr.mx_sb_len = SENSE_BUFF_LEN;
    io_hdr.sbp = senseBuff;
    io_hdr.timeout = DEF_TIMEOUT;
    io_hdr.pack_id = (int)to_block;

    // log_info("    write cdb: ");
    // for (k = 0; k < cdbsz; ++k)
    //     fprintf(stderr, "%02x ", wrCmd[k]);
    // fprintf(stderr, "\n");

    while (((res = ioctl(sg_fd, SG_IO, &io_hdr)) < 0) && (EINTR == errno))
        ;
    if (res < 0) {
        if (ENOMEM == errno)
            return -2;
        perror("writing (SG_IO) on sg device, error");
        return -1;
    }

    // log_info("      duration=%u ms\n", io_hdr.duration);
    switch (sg_err_category3(&io_hdr)) {
    case SG_LIB_CAT_CLEAN:
        break;
    case SG_LIB_CAT_RECOVERED:
        sg_chk_n_print3("writing, continue", &io_hdr, 1);
        break;
    case SG_LIB_CAT_MEDIA_CHANGED:
        sg_chk_n_print3("writing", &io_hdr, 1);
        return -3;
    default:
        sg_chk_n_print3("writing", &io_hdr, 1);
        return -1;
    }
    return 0;
}

static int sg_bread(struct dr_blkdev *dev, uint8_t *buf, uint64_t blk_id,
                    uint32_t blk_cnt)
{
    int res, size;

    if (dev->dev_fd < 0)
        return -1;

    size = blk_cnt * dev->block_size; 
    if ((ioctl(dev->dev_fd, SG_SET_RESERVED_SIZE, &size) < 0)) {
        fprintf(stderr, "SG_SET_RESERVED_SIZE error\n");
        return -1;
    }

    if ((res = sg_read(dev->dev_fd, buf, blk_cnt, blk_id, dev->block_size,
                       16, 0, 0)) != 0) {
        log_error("SCSI READ failed(%d)\n", res);
        return -1;
    }

    return 0;
}

static int sg_bwrite(struct dr_blkdev *dev, uint8_t *buf, uint64_t blk_id, 
                     uint32_t blk_cnt)
{
    int res, size;

    if (dev->dev_fd < 0)
        return -1;

    size = blk_cnt * dev->block_size; 
    if ((ioctl(dev->dev_fd, SG_SET_RESERVED_SIZE, &size) < 0)) {
        fprintf(stderr, "SG_SET_RESERVED_SIZE error\n");
        return -1;
    }

    if ((res = sg_write(dev->dev_fd, buf, blk_cnt, blk_id, dev->block_size,
                        16, 0, 0)) != 0) {
        log_error("SCSI WRITE failed(%d)\n", res);
        return -1;
    }
    return 0;
}

static int is_sg_device(const char *device)
{
    struct stat st;

    if (stat(device, &st) < 0)
        return -1;
    if (S_ISCHR(st.st_mode) && SCSI_GENERIC_MAJOR == major(st.st_rdev))
        return 0;
    return -1;
}

static int sg_open(struct dr_blkdev *dev)
{
    int sg_fd, k;
    const char *device_name = "/dev/sg0";

    if (is_sg_device(device_name)) {
        log_error("%s not a SCSI generic (sg) device\n", device_name);
        return -2;
    }

    if ((sg_fd = open(device_name, O_RDWR | O_EXCL | O_SYNC)) < 0) {
        log_error("cound not open %s for sg reading and writing\n", device_name);
        return -1;
    }
    
    if ((ioctl(sg_fd, SG_GET_VERSION_NUM, &k) < 0) || (k < 30000)) {
        fprintf(stderr, "%s doesn't seem to be an new sg device\n", device_name);
        close(sg_fd);
        return -1;
    }

    dev->dev_fd = sg_fd;
    return 0;
}

static void sg_close(struct dr_blkdev *dev)
{
    close(dev->dev_fd);
}

struct dr_blkdev sg_blkdev = {
    .devname = "sg",
    .block_size = 512,
    .open = sg_open,
    .close = sg_close,
    .bread = sg_bread,
    .bwrite = sg_bwrite,
};
