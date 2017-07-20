#ifndef _DISK_ROOT_CRC32C_H_
#define _DISK_ROOT_CRC32C_H_

#include <stdint.h>

/**@brief	CRC32 algorithm.
 * @param	crc input feed
 * @param 	buf input buffer
 * @param	size input buffer length (bytes)
 * @return	updated crc32 value
 */
uint32_t dr_crc32(uint32_t crc, const void *buf, uint32_t size);

/**@brief	CRC32C algorithm.
 * @param	crc input feed
 * @param 	buf input buffer
 * @param	length input buffer length (bytes)
 * @return	updated crc32c value
 */
uint32_t dr_crc32c(uint32_t crc, const void *buf, uint32_t size);

#endif /* _DISK_ROOT_CRC32C_H_ */
