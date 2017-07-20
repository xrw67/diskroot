#include "disk_root.h"

/**
 * MBR
 */
#define MBR_SIGNATURE 0xAA55
#define FS_TYPE_LINUX_NATIVE 0x83

#pragma pack(push, 1)

struct mbr_part_entry {
	uint8_t status;
	uint8_t chs1[3];
	uint8_t type;
	uint8_t chs2[3];
	uint32_t first_lba;
	uint32_t sectors;
};

struct mbr {
	uint8_t bootstrap[446];
	struct mbr_part_entry part_entry[4];
	uint16_t signature;
};

#pragma pack(pop)


uint32_t mbr_get_part_offset(struct dr_blkdev *dev, int index)
{
    struct mbr mbr;
    
    if (index >= 4)
        return -E_OUT_RANGE;
    if (dev->bread(dev, (uint8_t *)&mbr, 0, 1))
        return -E_DISK_READ;
    if (MBR_SIGNATURE != mbr.signature) /* Is MBR */
        return -E_MAGIC_NOT_MATCH;

    return mbr.part_entry[index].first_lba;
}
