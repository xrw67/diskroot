#include "ext4.h"
#include "crc32.h"
#include "disk_root.h"
#include <string.h>
#include <stdlib.h>

/**
 * block io operation
 */

static int ext4_block_rw(struct ext4_fs *fs, void *buf, uint64_t blk_id, uint32_t blk_cnt, int write)
{
    struct dr_blkdev *dev = fs->dev;

    uint32_t d = fs->block_size / dev->block_size;
    
    uint32_t dev_blk_cnt = d * blk_cnt;
    uint64_t dev_blk_id = d * blk_id + fs->dev_part_offset;

    if (write)
        return dev->bwrite(dev, buf, dev_blk_id, dev_blk_cnt);
    else
        return dev->bread(dev, buf, dev_blk_id, dev_blk_cnt);
}

int ext4_bread(struct ext4_fs *fs, void *buf, uint64_t blk_id, uint32_t blk_cnt)
{
    return ext4_block_rw(fs, buf, blk_id, blk_cnt, 0);
}

int ext4_bwrite(struct ext4_fs *fs, void *buf, uint64_t blk_id, uint32_t blk_cnt)
{
    return ext4_block_rw(fs, buf, blk_id, blk_cnt, 1);
}


/**
 * Block Cache
 */

int ext4_bcache_clear(struct ext4_fs *fs, struct ext4_bcache **head, int flush)
{
    while (*head) {
        struct ext4_bcache *p = *head;

        if (p->baddr && p->data && flush) {
            int rc = ext4_bwrite(fs, p->data, p->baddr, 1);
            if (rc)
                return rc;
        }

        *head = p->next;
        free(p);
    }

    return 0;
}
struct ext4_bcache *ext4_bcache_get(struct ext4_fs *fs, struct ext4_bcache **head, uint64_t baddr)
{
    struct ext4_bcache *p;

    for (p = *head; p; p = p->next) {
        if (p->baddr == baddr)
            return p;
    }

    p = malloc(sizeof(*p) + fs->block_size);
    if (p) {
        p->baddr = baddr;
        p->data = (char *)(&p[1]);
        p->next = (*head) ? (*head)->next : NULL;
        
        if (ext4_bread(fs, p->data, baddr, 1)) {
            free(p);
            return NULL;
        }
        
        *head = p;
    }

    return p;
}

/**
 * Super Block
 */

static inline int is_power_of(uint32_t a, uint32_t b)
{
	while (1) {
		if (a < b)
			return 0;
		if (a == b)
			return 1;
		if ((a % b) != 0)
			return 0;
		a = a / b;
	}
}

int ext4_sb_sparse(uint32_t group)
{
	if (group <= 1)
		return 1;

	if (!(group & 1))
		return 0;

	return (is_power_of(group, 7) || is_power_of(group, 5) ||
		is_power_of(group, 3));
}

int ext4_sb_is_super_in_bg(struct ext4_sblock *s, uint32_t group)
{
	if (ext4_sb_feature_ro_com(s, EXT4_FRO_COM_SPARSE_SUPER) &&
	    !ext4_sb_sparse(group))
		return 0;
	return 1;
}

uint32_t ext4_block_group_cnt(struct ext4_sblock *s)
{
	uint64_t blocks_count = ext4_sb_get_blocks_cnt(s);
	uint32_t blocks_per_group = ext4_get32(s, blocks_per_group);

	uint32_t block_groups_count = (uint32_t)(blocks_count / blocks_per_group);

	if (blocks_count % blocks_per_group)
		block_groups_count++;

	return block_groups_count;
}

uint32_t ext4_blocks_in_group_cnt(struct ext4_sblock *s, uint32_t bgid)
{
	uint32_t block_group_count = ext4_block_group_cnt(s);
	uint32_t blocks_per_group = ext4_get32(s, blocks_per_group);
	uint64_t total_blocks = ext4_sb_get_blocks_cnt(s);

	if (bgid < block_group_count - 1)
		return blocks_per_group;

	return (uint32_t)(total_blocks - ((block_group_count - 1) * blocks_per_group));
}


struct ext4_sblock *ext4_get_sb(struct ext4_fs *fs, struct ext4_bcache **head)
{
    struct ext4_bcache *p;

     if (fs->block_size == 1024) {
         p = ext4_bcache_get(fs, head, 1);
         if (p)
            return (struct ext4_sblock *)((char *)p->data);
     } else {
         p = ext4_bcache_get(fs, head, 0);
         if (p)
            return (struct ext4_sblock *)((char *)p->data + 1024);
     }

     return NULL;
}

static uint32_t ext4_sb_csum(struct ext4_sblock *s)
{
	return dr_crc32c(EXT4_CRC32_INIT, s,
			offsetof(struct ext4_sblock, checksum));
}

static void ext4_sb_set_csum(struct ext4_sblock *s)
{
	if (!ext4_sb_feature_ro_com(s, EXT4_FRO_COM_METADATA_CSUM))
		return;

	s->checksum = to_le32(ext4_sb_csum(s));
}

/**
 * Block Group Description
 */

static inline uint64_t ext4_first_bg_block_no(struct ext4_sblock *sb,
						                      uint32_t bgid)
{
	return (uint64_t)bgid * ext4_get32(sb, blocks_per_group) +
	       ext4_get32(sb, first_data_block);
}

static uint64_t ext4_get_descriptor_block(struct ext4_sblock *sb,
                        uint32_t bgid, uint32_t dsc_per_block)
{
	uint32_t first_meta_bg, dsc_id;
	int has_super = 0;
	dsc_id = bgid / dsc_per_block;
	first_meta_bg = ext4_sb_first_meta_bg(sb);

	int meta_bg = ext4_sb_feature_incom(sb, EXT4_FINCOM_META_BG);

	if (!meta_bg || dsc_id < first_meta_bg)
		return ext4_get32(sb, first_data_block) + dsc_id + 1;

	if (ext4_sb_is_super_in_bg(sb, bgid))
		has_super = 1;

	return (has_super + ext4_first_bg_block_no(sb, bgid));
}

struct ext4_bgroup *ext4_get_group_desc(struct ext4_fs *fs, struct ext4_sblock *sb, struct ext4_bcache **head, uint32_t bgid)
{
    /* Compute number of descriptors, that fits in one data block */
    uint32_t block_size = ext4_sb_get_block_size(sb);
    uint32_t dsc_cnt = block_size / ext4_sb_get_desc_size(sb);

    /* Block group descriptor table starts at the next block after
	 * superblock */
    uint64_t block_id = ext4_get_descriptor_block(sb, bgid, dsc_cnt);

    uint32_t offset = (bgid % dsc_cnt) * ext4_sb_get_desc_size(sb);

    struct ext4_bcache *bcache = ext4_bcache_get(fs, head, block_id);
    if (!bcache)
        return NULL;

    return (struct ext4_bgroup *)((char *)bcache->data + offset);
}

/**@brief CRC-16 look up table*/
static uint16_t const crc16_tab[256] = {
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241, 0xC601,
    0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440, 0xCC01, 0x0CC0,
    0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40, 0x0A00, 0xCAC1, 0xCB81,
    0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841, 0xD801, 0x18C0, 0x1980, 0xD941,
    0x1B00, 0xDBC1, 0xDA81, 0x1A40, 0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01,
    0x1DC0, 0x1C80, 0xDC41, 0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0,
    0x1680, 0xD641, 0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081,
    0x1040, 0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441, 0x3C00,
    0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41, 0xFA01, 0x3AC0,
    0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840, 0x2800, 0xE8C1, 0xE981,
    0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41, 0xEE01, 0x2EC0, 0x2F80, 0xEF41,
    0x2D00, 0xEDC1, 0xEC81, 0x2C40, 0xE401, 0x24C0, 0x2580, 0xE541, 0x2700,
    0xE7C1, 0xE681, 0x2640, 0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0,
    0x2080, 0xE041, 0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281,
    0x6240, 0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41, 0xAA01,
    0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840, 0x7800, 0xB8C1,
    0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41, 0xBE01, 0x7EC0, 0x7F80,
    0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40, 0xB401, 0x74C0, 0x7580, 0xB541,
    0x7700, 0xB7C1, 0xB681, 0x7640, 0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101,
    0x71C0, 0x7080, 0xB041, 0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0,
    0x5280, 0x9241, 0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481,
    0x5440, 0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841, 0x8801,
    0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40, 0x4E00, 0x8EC1,
    0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41, 0x4400, 0x84C1, 0x8581,
    0x4540, 0x8701, 0x47C0, 0x4680, 0x8641, 0x8201, 0x42C0, 0x4380, 0x8341,
    0x4100, 0x81C1, 0x8081, 0x4040};

uint16_t ext4_bg_crc16(uint16_t crc, const uint8_t *buffer, size_t len)
{
	while (len--)

		crc = (((crc >> 8) & 0xffU) ^
		       crc16_tab[(crc ^ *buffer++) & 0xffU]) &
		      0x0000ffffU;
	return crc;
}

/**
 * Block Allocate
 */

/**@brief Compute number of block group from block address.
 * @param sb superblock pointer.
 * @param baddr Absolute address of block.
 * @return Block group index
 */
uint32_t ext4_balloc_get_bgid_of_block(struct ext4_sblock *s,
				       uint64_t baddr)
{
	if (ext4_get32(s, first_data_block) && baddr)
		baddr--;

	return (uint32_t)(baddr / ext4_get32(s, blocks_per_group));
}

static uint32_t ext4_balloc_bitmap_csum(struct ext4_sblock *sb,
					void *bitmap)
{
	uint32_t checksum = 0;
	if (ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_METADATA_CSUM)) {
		uint32_t blocks_per_group = ext4_get32(sb, blocks_per_group);

		/* First calculate crc32 checksum against fs uuid */
		checksum = dr_crc32c(EXT4_CRC32_INIT, sb->uuid,
				sizeof(sb->uuid));
		/* Then calculate crc32 checksum against block_group_desc */
	}
	return checksum;
}

void ext4_balloc_set_bitmap_csum(struct ext4_sblock *sb,
				 struct ext4_bgroup *bg,
				 void *bitmap __unused)
{
	int desc_size = ext4_sb_get_desc_size(sb);
	uint32_t checksum = ext4_balloc_bitmap_csum(sb, bitmap);
	uint16_t lo_checksum = to_le16(checksum & 0xFFFF),
		 hi_checksum = to_le16(checksum >> 16);

	if (!ext4_sb_feature_ro_com(sb, EXT4_FRO_COM_METADATA_CSUM))
		return;

	/* See if we need to assign a 32bit checksum */
	bg->block_bitmap_csum_lo = lo_checksum;
	if (desc_size == EXT4_MAX_BLOCK_GROUP_DESCRIPTOR_SIZE)
		bg->block_bitmap_csum_hi = hi_checksum;

}

/**@brief Compute the starting block address of a block group
 * @param sb   superblock pointer.
 * @param bgid block group index
 * @return Block address
 */
uint64_t ext4_balloc_get_block_of_bgid(struct ext4_sblock *s,
				       uint32_t bgid)
{
	uint64_t baddr = 0;
	if (ext4_get32(s, first_data_block))
		baddr++;

	baddr += bgid * ext4_get32(s, blocks_per_group);
	return baddr;
}

int ext4_balloc_alloc_blocks(struct ext4_fs *fs, uint64_t *blocks, uint32_t blk_cnt)
{
    int r;
    uint64_t i = 0;
    struct ext4_bgroup *bg;
    struct ext4_bcache *bcache_head = NULL;
    uint64_t bmp_blk_adr;
    uint64_t sb_free_blocks;

    struct ext4_sblock *sb = ext4_get_sb(fs, &bcache_head);
    if (!sb)
        return -1;

    uint32_t block_group_count = ext4_block_group_cnt(sb);
    uint32_t count = block_group_count;

    while (count-- > 0) {
        uint32_t bgid = count;

        bg = ext4_get_group_desc(fs, sb, &bcache_head, bgid);
        if (!bg)
            goto failed;
        
        /* Load block with bitmap */
        bmp_blk_adr = ext4_bg_get_block_bitmap(bg, sb);

        struct ext4_bcache *bmp_bcache = ext4_bcache_get(fs, &bcache_head, bmp_blk_adr);
        if (!bmp_bcache)
            goto failed;

        char *b = bmp_bcache->data;

        /* Compute indexes */
        uint64_t first_in_bg = ext4_balloc_get_block_of_bgid(sb, bgid);
        uint32_t idx_in_bg = ext4_addr_to_idx_bg(sb, first_in_bg);
        uint32_t blk_in_bg = ext4_blocks_in_group_cnt(sb, bgid);
        uint32_t first_in_bg_index = ext4_addr_to_idx_bg(sb, first_in_bg);

        if (idx_in_bg < first_in_bg_index)
            idx_in_bg = first_in_bg_index;
        
        while (1) {
            uint32_t rel_blk_idx;

            if (ext4_bmap_bit_find_clr(b, idx_in_bg, blk_in_bg, &rel_blk_idx))
                break;

            ext4_bmap_bit_set(b, rel_blk_idx);
            ext4_balloc_set_bitmap_csum(sb, bg, b);
            
            /* Update block group free blocks count */
            uint32_t fb_cnt = ext4_bg_get_free_blocks_count(bg, sb);
            fb_cnt--;
            ext4_bg_set_free_blocks_count(bg, sb, fb_cnt);

            blocks[i++] = ext4_bg_idx_to_addr(sb, rel_blk_idx, bgid);
            
            if (i == blk_cnt)
                goto success;
        }
    }

success:
    /* Update superblock free blocks count */
    sb_free_blocks = ext4_sb_get_free_blocks_cnt(sb);
    sb_free_blocks -= blk_cnt;
    ext4_sb_set_free_blocks_cnt(sb, sb_free_blocks);
    ext4_sb_set_csum(sb);
    
    ext4_bcache_clear(fs, &bcache_head, 1);
    return 0;

failed:
    ext4_bcache_clear(fs, &bcache_head, 0);
    return -1;
}

int ext4_balloc_free_blocks(struct ext4_fs *fs, uint64_t *blk_ids, uint32_t blk_cnt)
{
    int i;
    uint32_t bgid;
    uint32_t index_in_group;
    struct ext4_bgroup *bg;
    uint64_t bmp_blk_adr;
    struct ext4_bcache *bmp_block;
    uint32_t free_blocks;
    uint64_t sb_free_blocks;
    struct ext4_bcache *bcache_head = NULL;

    struct ext4_sblock *sb = ext4_get_sb(fs, &bcache_head);
    if (!sb)
        return -1;

    for (i = 0; i < blk_cnt; ++i) {
        bgid = ext4_balloc_get_bgid_of_block(sb, blk_ids[i]);
        index_in_group = ext4_addr_to_idx_bg(sb, blk_ids[i]);

        bg = ext4_get_group_desc(fs, sb, &bcache_head, bgid);
        if (!bg)
            goto failed;

        /* Load block with bitmap */
        bmp_blk_adr = ext4_bg_get_block_bitmap(bg, sb);

        bmp_block = ext4_bcache_get(fs, &bcache_head, bmp_blk_adr);
        if (!bmp_block)
            goto failed;

        /* Modify bitmap */
        ext4_bmap_bit_clr(bmp_block->data, index_in_group);
        ext4_balloc_set_bitmap_csum(sb, bg, bmp_block->data);

        /* Update block group free blocks count */
        free_blocks = ext4_bg_get_free_blocks_count(bg, sb);
        free_blocks++;
        ext4_bg_set_free_blocks_count(bg, sb, free_blocks);
    }

    /* Update superblock free blocks count */
	sb_free_blocks = ext4_sb_get_free_blocks_cnt(sb);
	sb_free_blocks += blk_cnt;
	ext4_sb_set_free_blocks_cnt(sb, sb_free_blocks);
    ext4_sb_set_csum(sb);

    ext4_bcache_clear(fs, &bcache_head, 1);
    return 0;

failed:
    ext4_bcache_clear(fs, &bcache_head, 0);
    return -1;
}

/**
 * Block Bitmap
 */

int ext4_bmap_bit_find_clr(uint8_t *bmap, uint32_t sbit, uint32_t ebit, uint32_t *bit_id)
{
	uint32_t i;
	uint32_t bcnt = ebit - sbit;

	i = sbit;

	while (i & 7) {
		if (!bcnt)
			return -1;

		if (ext4_bmap_is_bit_clr(bmap, i)) {
			*bit_id = sbit;
			return 0;
		}

		i++;
		bcnt--;
	}

	sbit = i;
	bmap += (sbit >> 3);

	while (bcnt >= 8) {
		if (*bmap != 0xFF) {
			for (i = 0; i < 8; ++i) {
				if (ext4_bmap_is_bit_clr(bmap, i)) {
					*bit_id = sbit + i;
					return 0;
				}
			}
		}

		bmap += 1;
		bcnt -= 8;
		sbit += 8;
	}

	for (i = 0; i < bcnt; ++i) {
		if (ext4_bmap_is_bit_clr(bmap, i)) {
			*bit_id = sbit + i;
			return 0;
		}
	}

	return -1;
}
