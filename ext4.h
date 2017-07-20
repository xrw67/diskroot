#ifndef _DISK_ROOT_EXT4_H_
#define _DISK_ROOT_EXT4_H_

#include <stdint.h>
#include "ext4_types.h"

struct dr_blkdev;

/**
 * cache block for writing
 */
struct ext4_bcache {
	uint64_t baddr;
	uint8_t *data;
	struct ext4_bcache *next;
};

struct ext4_fs {
	struct dr_blkdev *dev;
	uint64_t dev_part_offset;
	uint32_t block_size;
};

int ext4_bcache_clear(struct ext4_fs *fs, struct ext4_bcache **head, int flush);
struct ext4_bcache *ext4_bcache_get(struct ext4_fs *fs, struct ext4_bcache **head, uint64_t baddr);

int ext4_bread(struct ext4_fs *fs, void *buf, uint64_t blk_id, uint32_t blk_cnt);
int ext4_bwrite(struct ext4_fs *fs, void *buf, uint64_t blk_id, uint32_t blk_cnt);

int ext4_balloc_alloc_blocks(struct ext4_fs *fs, uint64_t *blocks, uint32_t blk_cnt);
int ext4_balloc_free_blocks(struct ext4_fs *fs, uint64_t *blk_ids, uint32_t blk_cnt);

/**
 * Super Block
 */

/**@brief   Blocks count get stored in superblock.
 * @param   s superblock descriptor
 * @return  count of blocks*/
static inline uint64_t ext4_sb_get_blocks_cnt(struct ext4_sblock *s)
{
	return ((uint64_t)to_le32(s->blocks_count_hi) << 32) |
	       to_le32(s->blocks_count_lo);
}

/**@brief   Blocks count set  in superblock.
 * @param   s superblock descriptor
 * @return  count of blocks*/
static inline void ext4_sb_set_blocks_cnt(struct ext4_sblock *s, uint64_t cnt)
{
	s->blocks_count_lo = to_le32((cnt << 32) >> 32);
	s->blocks_count_hi = to_le32(cnt >> 32);
}

/**@brief   Free blocks count get stored in superblock.
 * @param   s superblock descriptor
 * @return  free blocks*/
static inline uint64_t ext4_sb_get_free_blocks_cnt(struct ext4_sblock *s)
{
	return ((uint64_t)to_le32(s->free_blocks_count_hi) << 32) |
	       to_le32(s->free_blocks_count_lo);
}

/**@brief   Free blocks count set.
 * @param   s superblock descriptor
 * @param   cnt new value of free blocks*/
static inline void ext4_sb_set_free_blocks_cnt(struct ext4_sblock *s,
					       uint64_t cnt)
{
	s->free_blocks_count_lo = to_le32((cnt << 32) >> 32);
	s->free_blocks_count_hi = to_le32(cnt >> 32);
}

/**@brief   Block size get from superblock.
 * @param   s superblock descriptor
 * @return  block size in bytes*/
static inline uint32_t ext4_sb_get_block_size(struct ext4_sblock *s)
{
	return 1024 << to_le32(s->log_block_size);
}

/**@brief   Block group descriptor size.
 * @param   s superblock descriptor
 * @return  block group descriptor size in bytes*/
static inline uint16_t ext4_sb_get_desc_size(struct ext4_sblock *s)
{
	uint16_t size = to_le16(s->desc_size);

	return size < EXT4_MIN_BLOCK_GROUP_DESCRIPTOR_SIZE
		   ? EXT4_MIN_BLOCK_GROUP_DESCRIPTOR_SIZE
		   : size;
}

/*************************Flags and features*********************************/

/**@brief   Support check of flag.
 * @param   s superblock descriptor
 * @param   v flag to check
 * @return  true if flag is supported*/
static inline int ext4_sb_check_flag(struct ext4_sblock *s, uint32_t v)
{
	return to_le32(s->flags) & v;
}

/**@brief   Support check of feature compatible.
 * @param   s superblock descriptor
 * @param   v feature to check
 * @return  true if feature is supported*/
static inline int ext4_sb_feature_com(struct ext4_sblock *s, uint32_t v)
{
	return to_le32(s->features_compatible) & v;
}

/**@brief   Support check of feature incompatible.
 * @param   s superblock descriptor
 * @param   v feature to check
 * @return  true if feature is supported*/
static inline int ext4_sb_feature_incom(struct ext4_sblock *s, uint32_t v)
{
	return to_le32(s->features_incompatible) & v;
}

/**@brief   Support check of read only flag.
 * @param   s superblock descriptor
 * @param   v flag to check
 * @return  true if flag is supported*/
static inline int ext4_sb_feature_ro_com(struct ext4_sblock *s, uint32_t v)
{
	return to_le32(s->features_read_only) & v;
}

/**@brief   Block group to flex group.
 * @param   s superblock descriptor
 * @param   block_group block group
 * @return  flex group id*/
static inline uint32_t ext4_sb_bg_to_flex(struct ext4_sblock *s,
					  uint32_t block_group)
{
	return block_group >> to_le32(s->log_groups_per_flex);
}

/**@brief   Flex block group size.
 * @param   s superblock descriptor
 * @return  flex bg size*/
static inline uint32_t ext4_sb_flex_bg_size(struct ext4_sblock *s)
{
	return 1 << to_le32(s->log_groups_per_flex);
}

/**@brief   Return first meta block group id.
 * @param   s superblock descriptor
 * @return  first meta_bg id */
static inline uint32_t ext4_sb_first_meta_bg(struct ext4_sblock *s)
{
	return to_le32(s->first_meta_bg);
}

/**
 * Block Group
 */

/**@brief Convert block address to relative index in block group.
 * @param sb Superblock pointer
 * @param baddr Block number to convert
 * @return Relative number of block
 */
static inline uint32_t ext4_addr_to_idx_bg(struct ext4_sblock *s,
						     ext4_fsblk_t baddr)
{
	if (ext4_get32(s, first_data_block) && baddr)
		baddr--;

	return baddr % ext4_get32(s, blocks_per_group);
}

/**@brief Convert relative block address in group to absolute address.
 * @param s Superblock pointer
 * @param index Relative block address
 * @param bgid Block group
 * @return Absolute block address
 */
static inline ext4_fsblk_t ext4_bg_idx_to_addr(struct ext4_sblock *s,
						     uint32_t index,
						     uint32_t bgid)
{
	if (ext4_get32(s, first_data_block))
		index++;

	return ext4_get32(s, blocks_per_group) * bgid + index;
}

/**@brief Get address of block with data block bitmap.
 * @param bg pointer to block group
 * @param s pointer to superblock
 * @return Address of block with block bitmap
 */
static inline uint64_t ext4_bg_get_block_bitmap(struct ext4_bgroup *bg,
						struct ext4_sblock *s)
{
	uint64_t v = to_le32(bg->block_bitmap_lo);

	if (ext4_sb_get_desc_size(s) > EXT4_MIN_BLOCK_GROUP_DESCRIPTOR_SIZE)
		v |= (uint64_t)to_le32(bg->block_bitmap_hi) << 32;

	return v;
}

/**@brief Get number of free blocks in block group.
 * @param bg Pointer to block group
 * @param sb Pointer to superblock
 * @return Number of free blocks in block group
 */
static inline uint32_t ext4_bg_get_free_blocks_count(struct ext4_bgroup *bg,
						     struct ext4_sblock *s)
{
	uint32_t v = to_le16(bg->free_blocks_count_lo);

	if (ext4_sb_get_desc_size(s) > EXT4_MIN_BLOCK_GROUP_DESCRIPTOR_SIZE)
		v |= (uint32_t)to_le16(bg->free_blocks_count_hi) << 16;

	return v;
}

/**@brief Set number of free blocks in block group.
 * @param bg Pointer to block group
 * @param s Pointer to superblock
 * @param cnt Number of free blocks in block group
 */
static inline void ext4_bg_set_free_blocks_count(struct ext4_bgroup *bg,
						 struct ext4_sblock *s,
						 uint32_t cnt)
{
	bg->free_blocks_count_lo = to_le16((cnt << 16) >> 16);
	if (ext4_sb_get_desc_size(s) > EXT4_MIN_BLOCK_GROUP_DESCRIPTOR_SIZE)
		bg->free_blocks_count_hi = to_le16(cnt >> 16);
}

/**@brief  Set checksum of block group.
 * @param bg Pointer to block group
 * @param crc Cheksum of block group
 */
static inline void ext4_bg_set_checksum(struct ext4_bgroup *bg, uint16_t crc)
{
	bg->checksum = to_le16(crc);
}

/**@brief Calculate CRC16 of the block group.
 * @param crc Init value
 * @param buffer Input buffer
 * @param len Sizeof input buffer
 * @return Computed CRC16*/
uint16_t ext4_bg_crc16(uint16_t crc, const uint8_t *buffer, size_t len);


/**
 * Block Bitmap
 */

/**@brief   Set bitmap bit.
 * @param   bmap bitmap
 * @param   bit bit to set*/
static inline void ext4_bmap_bit_set(uint8_t *bmap, uint32_t bit)
{
	*(bmap + (bit >> 3)) |= (1 << (bit & 7));
}

/**@brief   Clear bitmap bit.
 * @param   bmap bitmap buffer
 * @param   bit bit to clear*/
static inline void ext4_bmap_bit_clr(uint8_t *bmap, uint32_t bit)
{
	*(bmap + (bit >> 3)) &= ~(1 << (bit & 7));
}

/**@brief   Check if the bitmap bit is set.
 * @param   bmap bitmap buffer
 * @param   bit bit to check*/
static inline int ext4_bmap_is_bit_set(uint8_t *bmap, uint32_t bit)
{
	return (*(bmap + (bit >> 3)) & (1 << (bit & 7)));
}

/**@brief   Check if the bitmap bit is clear.
 * @param   bmap bitmap buffer
 * @param   bit bit to check*/
static inline int ext4_bmap_is_bit_clr(uint8_t *bmap, uint32_t bit)
{
	return !ext4_bmap_is_bit_set(bmap, bit);
}

/**@brief   Find first clear bit in bitmap.
 * @param   sbit start bit of search
 * @param   ebit end bit of search
 * @param   bit_id output parameter (first free bit)
 * @return  standard error code*/
int ext4_bmap_bit_find_clr(uint8_t *bmap, uint32_t sbit, uint32_t ebit,
			   uint32_t *bit_id);
			   
#endif /* _DISK_ROOT_EXT4_H_ */ 
