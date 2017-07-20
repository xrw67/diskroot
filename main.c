#include "disk_root.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/vfs.h> /* statfs() */
#include "utils.h"

int write_dr_header(struct dr_blkdev *dev, struct dr_header *hdr)
{
    int rc;
    char *blkbuf;
    uint32_t magic_ptr = dev->block_size - DR_MAGIC_SIZE;
    uint32_t boot_end = mbr_get_part_offset(dev, 0);

    if ((int)boot_end < 0)
        return (int)boot_end;

    blkbuf = malloc(dev->block_size);
    if (!blkbuf)
        return -E_NO_MEM;

    if (!dev->bread(dev, blkbuf, boot_end-1, 1)) {
        if (iszeromem(blkbuf, dev->block_size))
            goto done;
        if (0 == memcmp(blkbuf + magic_ptr, DR_MAGIC, DR_MAGIC_SIZE))
            goto done;
    }

    free(blkbuf);
    return -1;

done:
    memcpy(blkbuf + magic_ptr, DR_MAGIC, DR_MAGIC_SIZE);
    memcpy(blkbuf + magic_ptr - sizeof(*hdr), hdr, sizeof(*hdr));

    rc = dev->bwrite(dev, blkbuf, boot_end-1, 1);
    free(blkbuf);
    return rc;
}

int get_dr_header(struct dr_blkdev *dev, struct dr_header *hdr)
{
    int rc;
    char *blkbuf;
    uint32_t magic_ptr = dev->block_size - DR_MAGIC_SIZE;
    uint32_t boot_end = mbr_get_part_offset(dev, 0);
    
    if ((int)boot_end < 0)
        return (int)boot_end;

    blkbuf = malloc(dev->block_size);
    if (!blkbuf)
        return -E_NO_MEM;

    rc = dev->bread(dev, blkbuf, boot_end-1, 1);
    if (rc)
        goto out;

    if (memcmp(blkbuf + magic_ptr, DR_MAGIC, DR_MAGIC_SIZE)) {
        rc = -E_MAGIC_NOT_MATCH;
        goto out;
    }

    memcpy(hdr, blkbuf + magic_ptr - sizeof(*hdr), sizeof(*hdr));

out:
    free(blkbuf);
    return rc;
}

int hdroot_file_write(struct dr_blkdev *dev, uint8_t *buf, uint32_t size)
{
    int rc;

    rc = boot_zone_write_file(dev, buf, size);
    if (rc == -E_ZONE_OUT_RANGE)
        rc = ext4_zone_write_file(dev, buf, size);
    return 0;
}

int hdroot_file_read(struct dr_blkdev *dev, struct dr_header *hdr,
                     uint8_t *buf, uint32_t size)
{
    int rc = 0;

    if (hdr->zone_type == DR_BOOT_ZONE)
        rc = boot_zone_read_file(dev, hdr, buf, size);
    if (hdr->zone_type == DR_EXT4_ZONE)
        rc = ext4_zone_read_file(dev, hdr, buf, size);
    return rc;
}

int hdroot_file_delete(struct dr_blkdev *dev, struct dr_header *hdr)
{
    int rc = 0;

    if (hdr->zone_type == DR_EXT4_ZONE)
        rc = ext4_zone_delete_file(dev, hdr);
    return rc;
}

static void usage(const char *procname)
{
    printf("Usage:\n");
    printf("\t%s -w <filename>    Write file\n", procname);
    printf("\t%s -r <filename>    Read file\n", procname);
    printf("\t%s -d               Delete file\n", procname);
}

#define OP_WRITE  1
#define OP_READ   2
#define OP_DELETE 3

int main(int argc, char **argv)
{
    int i;
    int op = 0;
    char  *filename = NULL;
    struct dr_header hdr;
    struct dr_blkdev *dev = &sg_blkdev;

    int file_size;
    uint8_t *file_buf = NULL;

    printf("Disk Root, Version:%s\n", DISKROOT_VERSION);

    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-w")) {
            op = OP_WRITE;
            filename = argv[++i];
        }
        if (!strcmp(argv[i], "-r")) {
            op = OP_READ;
            filename = argv[++i];
        }
        if (!strcmp(argv[i], "-d"))
            op = OP_DELETE;
        if (!strcmp(argv[i], "-f"))
            dev = &file_blkdev;
    }

    if (op == 0) {
        usage(argv[0]);
        return 0;
    }

    if (dev->open(dev)) {
        printf("open dev failed\n");
        return 0;
    }

    /* Write file */
    if (op == OP_WRITE) {
        log_info("Writing file...\n");
        file_size = get_file_size(filename);

        file_buf = malloc(file_size);
        if (!file_buf)
            goto out;

        if (read_file(filename, file_buf, &file_size))
            goto out;

        if (hdroot_file_write(dev, file_buf, file_size))
            log_error("Write file error\n");

        log_info("Write file... done\n");
        goto out;
    }
    
    /* Read data */
    if (op == OP_READ) {
        log_info("Read file...\n");

        if (get_dr_header(dev, &hdr)) {
            printf("Get hdroot info failed\n");
            goto out;
        }

        if (hdr.f_size == 0) {
            printf("File size is 0\n");
            goto out;
        }
        file_size = hdr.f_size;

        if ((file_buf = malloc(file_size)) == NULL) {
            printf("alloc memory failed\n");
            goto out;
        }
        
        if (hdroot_file_read(dev, &hdr, file_buf, file_size)) {
            log_error("Read file error\n");
            goto out;
        }

        if (write_file(filename, file_buf, file_size))
            log_error("write file %s error\n", filename);     
    
        log_info("Read file... done\n");
        goto out;
    }

    if (op == OP_DELETE) {
        log_info("Delete file...\n");

        i =get_dr_header(dev, &hdr);
        if (i == -E_MAGIC_NOT_MATCH) {
            log_info("No file in disk! Exit.\n");
            goto out;
        }
        if (i < 0) {
            printf("Get hdroot info failed\n");
            goto out;
        }

        if (hdroot_file_delete(dev, &hdr))
            log_error("delete file error\n");

        log_info("Delete file... done\n");
        goto out;
    }

out:
    if (file_buf)
        free(file_buf);
    dev->close(dev);
    return 0;
}
