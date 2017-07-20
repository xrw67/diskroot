/** 
 * +------------+
 * |  block1    |
 * |  block2    |
 * |  ......    |
 * | next_index | -> +-----------+
 * +------------+    | block N+1 |
 *                   | ......... |
 *                   +-----------+
 */

#include "ext4.h"
#include "crc32.h"
#include "disk_root.h"
#include "utils.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

void dump_block_list(uint64_t *blocks, uint32_t blk_cnt)
{
    int i;

    printf("Block list (%u):", blk_cnt);

    for (i = 0; i < blk_cnt; ++i) {
        if ((i % 10) == 0)
            printf("\n%6d: ", i);
        printf("%lu ", blocks[i]);
    }
    printf("\n");
}

static int ext4_fs_init(struct ext4_fs *fs, struct dr_blkdev *dev)
{
    struct ext4_sblock sb;
    
    fs->dev = dev;
    fs->dev_part_offset = mbr_get_part_offset(dev, 0);
    fs->block_size = 1024;

    if ((int)fs->dev_part_offset < 0)
        return (int)fs->dev_part_offset;

    if (ext4_bread(fs, &sb, 1, 1))
        return -E_DISK_READ;

    if (sb.magic != EXT4_SUPERBLOCK_MAGIC)
        return -E_MAGIC_NOT_MATCH;

    fs->block_size = 1024 << sb.log_block_size;
    
    return 0;
}

static int ext4_bwrite_one(struct ext4_fs *fs, void *buf, int buf_size, uint64_t blk_id)
{    
    if (buf_size <= 0)
        return 0;

    if (fs->block_size > buf_size) {
        int rc;
        char *tmp = malloc(fs->block_size);
        if (!tmp)
            return -E_NO_MEM;

        memcpy(tmp, buf, buf_size);
        memset(tmp + buf_size, 0, fs->block_size - buf_size);
        
        rc = ext4_bwrite(fs, tmp, blk_id, 1);
        
        free(tmp);
        return rc;
    }

    return ext4_bwrite(fs, buf, blk_id, 1);
}

uint32_t ext4_calc_block_cnt(uint32_t block_size, uint32_t file_size)
{
    uint32_t data_cnt = (file_size + block_size -1) / block_size;
    int one_idx_limit = block_size / sizeof(uint64_t) - 1;

    uint32_t idx_cnt = data_cnt / one_idx_limit;

    if (data_cnt % one_idx_limit)
        idx_cnt++;
    
    return idx_cnt + data_cnt;
}

int ext4_zone_read_file(struct dr_blkdev *dev, const struct dr_header *hdr,
                        uint8_t *buf, uint32_t buf_size)
{
    int rc;
    int read_bytes;
    char *blk_buf;

    uint64_t *idx_buf;
    uint32_t idx_ptr = 0;
    uint32_t one_idx_limit;

    struct ext4_fs fs;

    rc = ext4_fs_init(&fs, dev);
    if (rc)
        return rc;

    if (buf_size < hdr->f_size)
        return -E_BUFFER_TO_SMALL;

    blk_buf = malloc(fs.block_size);
    if (!blk_buf)
        return -E_NO_MEM;

    idx_buf = malloc(fs.block_size);
    if (!idx_buf) {
        free(blk_buf);
        return -E_NO_MEM;
    }

    /* read first index */
    rc = ext4_bread(&fs, idx_buf, hdr->f_offset, 1);
    if (rc)
        goto out;
    dump_block_list(idx_buf, fs.block_size / sizeof(uint64_t));
    printf("\nindex: %lu\n", hdr->f_offset);

    one_idx_limit = fs.block_size / sizeof(uint64_t) - 1;

    while (idx_buf[idx_ptr] != 0) {
        if (idx_ptr == one_idx_limit) {
            /* read next index */
            uint64_t new_id = idx_buf[idx_ptr];

            memset(idx_buf, 0, fs.block_size);
            rc = ext4_bread(&fs, idx_buf, new_id, 1);
            if (rc)
                goto out;
            dump_block_list(idx_buf, idx_ptr+1);
            printf("\nindex: %lu\n", new_id);
            idx_ptr = 0;
        }

        rc = ext4_bread(&fs, blk_buf, idx_buf[idx_ptr++], 1);
        if (rc)
            goto out;
        printf("%lu ", idx_buf[idx_ptr-1]);
        
        read_bytes = (buf_size > fs.block_size) ? fs.block_size : buf_size;
        memcpy(buf, blk_buf, read_bytes);
        
        buf += read_bytes;
        buf_size -= read_bytes;
    }

    if (buf_size != 0)
        printf("read error, file_size=%lu, readed=%lu\n", hdr->f_size, hdr->f_size - buf_size);
out:
    free(blk_buf);
    free(idx_buf);
    return rc;
}

int ext4_zone_delete_file(struct dr_blkdev *dev, struct dr_header *hdr)
{
    int rc;
    uint64_t *blocks;
    uint32_t block_cnt, block_ptr = 0;

    uint64_t *idx_buf;
    uint32_t idx_ptr = 0;
    uint32_t one_idx_limit;

    struct ext4_fs fs;
    struct dr_header empty_hdr;

    rc = ext4_fs_init(&fs, dev);
    if (rc)
        return rc;

    block_cnt = ext4_calc_block_cnt(fs.block_size, hdr->f_size);

    blocks = malloc(sizeof(uint64_t) * block_cnt);
    if (!blocks)
        return -E_NO_MEM;

    memset(blocks, 0, sizeof(uint64_t) * block_cnt);
    blocks[block_ptr++] = hdr->f_offset;

    idx_buf = malloc(fs.block_size);
    if (!idx_buf) {
        free(blocks);
        return -E_NO_MEM;
    }

    /* read first index block */
    rc = ext4_bread(&fs, idx_buf, hdr->f_offset, 1);
    if (rc)
        goto out;

    one_idx_limit = fs.block_size / sizeof(uint64_t) - 1;

    while (idx_buf[idx_ptr] != 0) {
        if (idx_ptr == one_idx_limit) {
            /* save and read next index block */
            uint64_t idx_id = idx_buf[idx_ptr];

            blocks[block_ptr++] = idx_id;

            memset(idx_buf, 0, fs.block_size);
            rc = ext4_bread(&fs, idx_buf, idx_id, 1);
            if (rc)
                goto out;

            idx_ptr = 0;
        }

        blocks[block_ptr++] = idx_buf[idx_ptr++];
    }

    rc = ext4_balloc_free_blocks(&fs, blocks, block_cnt);

    dump_block_list(blocks, block_cnt);

    /* empty header */
    memset(&empty_hdr, 0, sizeof(empty_hdr));
    rc = write_dr_header(dev, &empty_hdr);
    if (rc)
        goto out;

out:
    free(blocks);
    free(idx_buf);
    return rc;
}

int ext4_zone_write_file(struct dr_blkdev *dev, const uint8_t *data, uint32_t data_size)
{
    int rc;
    uint32_t block_cnt;
    uint64_t *blocks = NULL;
    uint32_t blk_ptr = 0;
    
    uint64_t *idx_buf;
    uint32_t idx_ptr;
    uint64_t idx_blk_id;
    uint32_t one_idx_limit;

    uint32_t sum;

    struct dr_header hdr;
    
    struct ext4_fs fs;

    rc = ext4_fs_init(&fs, dev);
    if (rc)
        return rc;

    block_cnt = ext4_calc_block_cnt(fs.block_size, data_size);
    if (block_cnt < 2)
        return -E_NO_BLOCKS;

    blocks = malloc(sizeof(uint64_t) * block_cnt);
    if (!blocks)
        return -E_NO_MEM;
    memset(blocks, 0, sizeof(uint64_t) * block_cnt);

    rc = ext4_balloc_alloc_blocks(&fs, blocks, block_cnt);
    if (rc) {
        free(blocks);
        return rc;
    }

    //log_info("ext4_balloc_alloc_blocks\n");
    //dump_block_list(blocks, block_cnt);

    hdr.zone_type = DR_EXT4_ZONE;
    hdr.f_offset = blocks[0];
    hdr.f_size = data_size;
    hdr.f_csum = dr_crc32c(DR_CRC32C_INIT, data, data_size);

    /* write data and index block*/

    idx_buf = malloc(fs.block_size);
    if (!idx_buf) {
        free(blocks);
        return -E_NO_MEM;
    }
    memset(idx_buf, 0, fs.block_size);

    one_idx_limit = fs.block_size / sizeof(uint64_t) - 1;

    idx_blk_id = blocks[blk_ptr++];
    idx_ptr = sum = 0;
    while (sum < data_size) {
        uint64_t new_id = blocks[blk_ptr++];
        
        if (idx_ptr == one_idx_limit) {
            /* write current index */
            idx_buf[idx_ptr] = new_id;
            rc = ext4_bwrite(&fs, idx_buf, idx_blk_id, 1);
            if (rc)
                goto out;
            printf("\nindex: %lu\n", idx_blk_id);
            dump_block_list(idx_buf, idx_ptr+1);

            /* get new index */
            memset(idx_buf, 0, fs.block_size);
            idx_blk_id = new_id;
            idx_ptr = 0;
            continue;
        }

        if (data_size - sum < fs.block_size) {
            /* this is last block */
            rc = ext4_bwrite_one(&fs, (char *)data + sum, data_size - sum, new_id);
            if (rc)
                goto out;
            printf("%lu (last)\n", new_id);

            idx_buf[idx_ptr++] = new_id;
            break;
        }

        rc = ext4_bwrite(&fs, (char *)data + sum, new_id, 1);
        if (rc)
            goto out;
        printf("%lu ", new_id);

        idx_buf[idx_ptr++] = new_id;
        sum += fs.block_size;
    }

    if (idx_ptr > 0) {
        rc = ext4_bwrite(&fs, idx_buf, idx_blk_id, 1);
        if (rc)
            goto out;
        printf("\nindex: %lu （last）\n", idx_blk_id);
    }

    /* write hdroot header */
    rc = write_dr_header(dev, &hdr);
    if (rc)
        goto out;

out:
    if (idx_buf)
        free(idx_buf);

    if (blocks) {
        if (rc)
            ext4_balloc_free_blocks(&fs, blocks, block_cnt);

        free(blocks);
    }

    return rc;
}

