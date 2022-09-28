#ifndef patchfinder8_h
#define patchfinder8_h

#include <stdint.h>
#include <string.h>

uint32_t find_mount8(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_cs_enforcement_disable_amfi8(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_sandbox_call_i_can_has_debugger8(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_vn_getpath8(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_memcmp8(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_sb_patch8(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_p_bootargs8(uint32_t region, uint8_t* kdata, size_t ksize);
#endif /* patchfinder8_h */
