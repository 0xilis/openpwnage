#include <stdint.h>
#include <string.h>
#include "patchfinder8.h"

static uint32_t bit_range(uint32_t x, int start, int end)
{
    x = (x << (31 - start)) >> (31 - start);
    x = (x >> end);
    return x;
}

static uint32_t ror(uint32_t x, int places)
{
    return (x >> places) | (x << (32 - places));
}

static int thumb_expand_imm_c(uint16_t imm12)
{
    if(bit_range(imm12, 11, 10) == 0)
    {
        switch(bit_range(imm12, 9, 8))
        {
            case 0:
                return bit_range(imm12, 7, 0);
            case 1:
                return (bit_range(imm12, 7, 0) << 16) | bit_range(imm12, 7, 0);
            case 2:
                return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 8);
            case 3:
                return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 16) | (bit_range(imm12, 7, 0) << 8) | bit_range(imm12, 7, 0);
            default:
                return 0;
        }
    } else
    {
        uint32_t unrotated_value = 0x80 | bit_range(imm12, 6, 0);
        return ror(unrotated_value, bit_range(imm12, 11, 7));
    }
}

static int insn_is_32bit(uint16_t* i)
{
    return (*i & 0xe000) == 0xe000 && (*i & 0x1800) != 0x0;
}

static int insn_is_ldr_literal(uint16_t* i)
{
    return (*i & 0xF800) == 0x4800 || (*i & 0xFF7F) == 0xF85F;
}

static int insn_ldr_literal_rt(uint16_t* i)
{
    if((*i & 0xF800) == 0x4800)
        return (*i >> 8) & 7;
    else if((*i & 0xFF7F) == 0xF85F)
        return (*(i + 1) >> 12) & 0xF;
    else
        return 0;
}

static int insn_ldr_literal_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x4800)
        return (*i & 0xFF) << 2;
    else if((*i & 0xFF7F) == 0xF85F)
        return (*(i + 1) & 0xFFF) * (((*i & 0x0800) == 0x0800) ? 1 : -1);
    else
        return 0;
}

// TODO: More encodings
static int insn_is_ldrb_imm(uint16_t* i)
{
    return (*i & 0xF800) == 0x7800;
}

static int insn_ldrb_imm_rt(uint16_t* i)
{
    return (*i & 7);
}

static int insn_ldrb_imm_rn(uint16_t* i)
{
    return ((*i >> 3) & 7);
}

static int insn_ldrb_imm_imm(uint16_t* i)
{
    return ((*i >> 6) & 0x1F);
}

static int insn_is_ldr_reg(uint16_t* i)
{
    if((*i & 0xFE00) == 0x5800)
        return 1;
    else if((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return 1;
    else
        return 0;
}

static int insn_ldr_reg_rn(uint16_t* i)
{
    if((*i & 0xFE00) == 0x5800)
        return (*i >> 3) & 0x7;
    else if((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return (*i & 0xF);
    else
        return 0;
}

static int insn_ldr_reg_lsl(uint16_t* i)
{
    if((*i & 0xFE00) == 0x5800)
        return 0;
    else if((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return (*(i + 1) >> 4) & 0x3;
    else
        return 0;
}

static int insn_is_add_reg(uint16_t* i)
{
    if((*i & 0xFE00) == 0x1800)
        return 1;
    else if((*i & 0xFF00) == 0x4400)
        return 1;
    else if((*i & 0xFFE0) == 0xEB00)
        return 1;
    else
        return 0;
}

static int insn_add_reg_rd(uint16_t* i)
{
    if((*i & 0xFE00) == 0x1800)
        return (*i & 7);
    else if((*i & 0xFF00) == 0x4400)
        return (*i & 7) | ((*i & 0x80) >> 4) ;
    else if((*i & 0xFFE0) == 0xEB00)
        return (*(i + 1) >> 8) & 0xF;
    else
        return 0;
}

static int insn_add_reg_rn(uint16_t* i)
{
    if((*i & 0xFE00) == 0x1800)
        return ((*i >> 3) & 7);
    else if((*i & 0xFF00) == 0x4400)
        return (*i & 7) | ((*i & 0x80) >> 4) ;
    else if((*i & 0xFFE0) == 0xEB00)
        return (*i & 0xF);
    else
        return 0;
}

static int insn_add_reg_rm(uint16_t* i)
{
    if((*i & 0xFE00) == 0x1800)
        return (*i >> 6) & 7;
    else if((*i & 0xFF00) == 0x4400)
        return (*i >> 3) & 0xF;
    else if((*i & 0xFFE0) == 0xEB00)
        return *(i + 1) & 0xF;
    else
        return 0;
}

static int insn_is_movt(uint16_t* i)
{
    return (*i & 0xFBF0) == 0xF2C0 && (*(i + 1) & 0x8000) == 0;
}

static int insn_movt_rd(uint16_t* i)
{
    return (*(i + 1) >> 8) & 0xF;
}

static int insn_movt_imm(uint16_t* i)
{
    return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
}

static int insn_is_mov_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x2000)
        return 1;
    else if((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return 1;
    else if((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return 1;
    else
        return 0;
}

static int insn_mov_imm_rd(uint16_t* i)
{
    if((*i & 0xF800) == 0x2000)
        return (*i >> 8) & 7;
    else if((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return (*(i + 1) >> 8) & 0xF;
    else if((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return (*(i + 1) >> 8) & 0xF;
    else
        return 0;
}

static int insn_mov_imm_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x2000)
        return *i & 0xF;
    else if((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return thumb_expand_imm_c(((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF));
    else if((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
    else
        return 0;
}

static int insn_is_push(uint16_t* i)
{
    if((*i & 0xFE00) == 0xB400)
        return 1;
    else if(*i == 0xE92D)
        return 1;
    else if(*i == 0xF84D && (*(i + 1) & 0x0FFF) == 0x0D04)
        return 1;
    else
        return 0;
}

static int insn_push_registers(uint16_t* i)
{
    if((*i & 0xFE00) == 0xB400)
        return (*i & 0x00FF) | ((*i & 0x0100) << 6);
    else if(*i == 0xE92D)
        return *(i + 1);
    else if(*i == 0xF84D && (*(i + 1) & 0x0FFF) == 0x0D04)
        return 1 << ((*(i + 1) >> 12) & 0xF);
    else
        return 0;
}

static int insn_is_preamble_push(uint16_t* i)
{
    return insn_is_push(i) && (insn_push_registers(i) & (1 << 14)) != 0;
}

static int insn_str_imm_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x6000)
        return (*i & 0x07C0) >> 4;
    else if((*i & 0xF800) == 0x9000)
        return (*i & 0xFF) << 2;
    else if((*i & 0xFFF0) == 0xF8C0)
        return (*(i + 1) & 0xFFF);
    else if((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*(i + 1) & 0xFF);
    else
        return 0;
}

static int insn_str_imm_rt(uint16_t* i)
{
    if((*i & 0xF800) == 0x6000)
        return (*i & 7);
    else if((*i & 0xF800) == 0x9000)
        return (*i >> 8) & 7;
    else if((*i & 0xFFF0) == 0xF8C0)
        return (*(i + 1) >> 12) & 0xF;
    else if((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*(i + 1) >> 12) & 0xF;
    else
        return 0;
}

static int insn_str_imm_rn(uint16_t* i)
{
    if((*i & 0xF800) == 0x6000)
        return (*i >> 3) & 7;
    else if((*i & 0xF800) == 0x9000)
        return 13;
    else if((*i & 0xFFF0) == 0xF8C0)
        return (*i & 0xF);
    else if((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*i & 0xF);
    else
        return 0;
}

// Given an instruction, search backwards until an instruction is found matching the specified criterion.
static uint16_t* find_last_insn_matching(uint32_t region, uint8_t* kdata, size_t ksize, uint16_t* current_instruction, int (*match_func)(uint16_t*))
{
    while((uintptr_t)current_instruction > (uintptr_t)kdata)
    {
        if(insn_is_32bit(current_instruction - 2) && !insn_is_32bit(current_instruction - 3))
        {
            current_instruction -= 2;
        } else
        {
            --current_instruction;
        }

        if(match_func(current_instruction))
        {
            return current_instruction;
        }
    }

    return NULL;
}

// Given an instruction and a register, find the PC-relative address that was stored inside the register by the time the instruction was reached.
static uint32_t find_pc_rel_value(uint32_t region, uint8_t* kdata, size_t ksize, uint16_t* insn, int reg)
{
    // Find the last instruction that completely wiped out this register
    int found = 0;
    uint16_t* current_instruction = insn;
    while((uintptr_t)current_instruction > (uintptr_t)kdata)
    {
        if(insn_is_32bit(current_instruction - 2))
        {
            current_instruction -= 2;
        } else
        {
            --current_instruction;
        }

        if(insn_is_mov_imm(current_instruction) && insn_mov_imm_rd(current_instruction) == reg)
        {
            found = 1;
            break;
        }

        if(insn_is_ldr_literal(current_instruction) && insn_ldr_literal_rt(current_instruction) == reg)
        {
            found = 1;
            break;
        }
    }

    if(!found)
        return 0;

    // Step through instructions, executing them as a virtual machine, only caring about instructions that affect the target register and are commonly used for PC-relative addressing.
    uint32_t value = 0;
    while((uintptr_t)current_instruction < (uintptr_t)insn)
    {
        if(insn_is_mov_imm(current_instruction) && insn_mov_imm_rd(current_instruction) == reg)
        {
            value = insn_mov_imm_imm(current_instruction);
        } else if(insn_is_ldr_literal(current_instruction) && insn_ldr_literal_rt(current_instruction) == reg)
        {
            value = *(uint32_t*)(kdata + (((((uintptr_t)current_instruction - (uintptr_t)kdata) + 4) & 0xFFFFFFFC) + insn_ldr_literal_imm(current_instruction)));
        } else if(insn_is_movt(current_instruction) && insn_movt_rd(current_instruction) == reg)
        {
            value |= insn_movt_imm(current_instruction) << 16;
        } else if(insn_is_add_reg(current_instruction) && insn_add_reg_rd(current_instruction) == reg)
        {
            if(insn_add_reg_rm(current_instruction) != 15 || insn_add_reg_rn(current_instruction) != reg)
            {
                // Can't handle this kind of operation!
                return 0;
            }

            value += ((uintptr_t)current_instruction - (uintptr_t)kdata) + 4;
        }

        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }

    return value;
}

// Find PC-relative references to a certain address (relative to kdata). This is basically a virtual machine that only cares about instructions used in PC-relative addressing, so no branches, etc.
static uint16_t* find_literal_ref(uint32_t region, uint8_t* kdata, size_t ksize, uint16_t* insn, uint32_t address)
{
    uint16_t* current_instruction = insn;
    uint32_t value[16];
    memset(value, 0, sizeof(value));

    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_mov_imm(current_instruction))
        {
            value[insn_mov_imm_rd(current_instruction)] = insn_mov_imm_imm(current_instruction);
        } else if(insn_is_ldr_literal(current_instruction))
        {
            uintptr_t literal_address  = (uintptr_t)kdata + ((((uintptr_t)current_instruction - (uintptr_t)kdata) + 4) & 0xFFFFFFFC) + insn_ldr_literal_imm(current_instruction);
            if(literal_address >= (uintptr_t)kdata && (literal_address + 4) <= ((uintptr_t)kdata + ksize))
            {
                value[insn_ldr_literal_rt(current_instruction)] = *(uint32_t*)(literal_address);
            }
        } else if(insn_is_movt(current_instruction))
        {
            int reg = insn_movt_rd(current_instruction);
            value[reg] |= insn_movt_imm(current_instruction) << 16;
            if(value[reg] == address)
            {
                return current_instruction;
            }
        } else if(insn_is_add_reg(current_instruction))
        {
            int reg = insn_add_reg_rd(current_instruction);
            if(insn_add_reg_rm(current_instruction) == 15 && insn_add_reg_rn(current_instruction) == reg)
            {
                value[reg] += ((uintptr_t)current_instruction - (uintptr_t)kdata) + 4;
                if(value[reg] == address)
                {
                    return current_instruction;
                }
            }
        }

        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }

    return NULL;
}

struct find_search_mask
{
    uint16_t mask;
    uint16_t value;
};

// Search the range of kdata for a series of 16-bit values that match the search mask.
static uint16_t* find_with_search_mask8(uint32_t region, uint8_t* kdata, size_t ksize, int num_masks, const struct find_search_mask* masks)
{
    uint16_t* end = (uint16_t*)(kdata + ksize - (num_masks * sizeof(uint16_t)));
    uint16_t* cur;
    for(cur = (uint16_t*) kdata; cur <= end; ++cur)
    {
        int matched = 1;
        int i;
        for(i = 0; i < num_masks; ++i)
        {
            if((*(cur + i) & masks[i].mask) != masks[i].value)
            {
                matched = 0;
                break;
            }
        }

        if(matched)
            return cur;
    }

    return NULL;
}

static uint32_t find_memmove_arm8(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const uint8_t search[] = {0x00, 0x00, 0x52, 0xE3, 0x01, 0x00, 0x50, 0x11, 0x1E, 0xFF, 0x2F, 0x01, 0xB1, 0x40, 0x2D, 0xE9};
    void* ptr = memmem(kdata, ksize, search, sizeof(search));
    if(!ptr)
        return 0;

    return ((uintptr_t)ptr) - ((uintptr_t)kdata);
}

static uint32_t find_memmove_thumb8(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const uint8_t search[] = {0x03, 0x46, 0x08, 0x46, 0x19, 0x46, 0x80, 0xB5};
    void* ptr = memmem(kdata, ksize, search, sizeof(search));
    if(!ptr)
        return 0;

    return ((uintptr_t)ptr + 6 + 1) - ((uintptr_t)kdata);
}

// Write 1 here.
uint32_t find_cs_enforcement_disable_amfi8(uint32_t region, uint8_t* kdata, size_t ksize)
{
    // Find a function referencing cs_enforcement_disable_amfi
    const uint8_t search_function[] = {0x20, 0x68, 0x40, 0xF4, 0x40, 0x70, 0x20, 0x60, 0x00, 0x20, 0x90, 0xBD};
    uint8_t* ptr = memmem(kdata, ksize, search_function, sizeof(search_function));
    if(!ptr)
        return 0;

    // Only LDRB in there should try to dereference cs_enforcement_disable_amfi
    uint16_t* ldrb = find_last_insn_matching(region, kdata, ksize, (uint16_t*) ptr, insn_is_ldrb_imm);
    if(!ldrb)
        return 0;

    // Weird, not the right one.
    if(insn_ldrb_imm_imm(ldrb) != 0 || insn_ldrb_imm_rt(ldrb) > 12)
        return 0;

    // See what address that LDRB is dereferencing
    return find_pc_rel_value(region, kdata, ksize, ldrb, insn_ldrb_imm_rn(ldrb));
}

// Write this with a jump to the sandbox hook, then write a trampoline back to just after the jump you wrote here. Sandbox hook should look at the path in *(r3 + 0x14) and force
// it to be allowed if it is outside of /private/var/mobile, or inside of /private/var/mobile/Library/Preferences but not /private/var/mobile/Library/Preferences/com.apple*
// To force it to allow, *r0 = 0 and *(r0 + 0x4) = 0x18. If not, just call the original function via the trampoline.
uint32_t find_sb_patch8(uint32_t region, uint8_t* kdata, size_t ksize)
{
    // Find location of the "control_name" string.
    uint8_t* control_name = memmem(kdata, ksize, "control_name", sizeof("control_name"));
    if(!control_name)
        return 0;

    // Find a reference to the "control_name" string.
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)control_name - (uintptr_t)kdata);
    if(!ref)
        return 0;

    // Find the start of the function referencing "control_name"
    uint16_t* fn_start = ref;
    while(1)
    {
        fn_start = find_last_insn_matching(region, kdata, ksize, fn_start, insn_is_push);
        if(!fn_start)
            return 0;

        uint16_t registers = insn_push_registers(fn_start);
        // We match PUSH {R0, R1} as well to detect an already patched version.
        if((registers & (1 << 14)) != 0 || (registers & (1 << 0 | 1 << 1)) == (1 << 0 | 1 << 1))
            break;
    }

    return ((uintptr_t)fn_start) - ((uintptr_t)kdata);
}

// Utility function, necessary for the sandbox hook.
uint32_t find_vn_getpath8(uint32_t region, uint8_t* kdata, size_t ksize)
{
    // Find a string inside the vn_getpath function
    const struct  find_search_mask search_masks_84[] =
    {
        {0xF8FF, 0x2001},
        {0xFFFF, 0xE9CD},
        {0x0000, 0x0000},
        {0xFF00, 0x4600},
        {0xFF00, 0x4600},
        {0xFF00, 0x4600},
        {0xFF00, 0x4600}
    };

    const struct find_search_mask search_masks[] =
    {
        {0xFF00, 0x4600},
        {0xF8FF, 0x2001},
        {0xFF00, 0x4600},
        {0xFF00, 0x4600},
        {0xFFFF, 0xE9CD},
        {0x0000, 0x0000},
        {0xFF00, 0x4600},
        {0xFF00, 0x4600}
    };

    uint16_t* insn = find_with_search_mask8(region, kdata, ksize, sizeof(search_masks_84) / sizeof(*search_masks_84), search_masks_84);
    if(!insn)
        insn = find_with_search_mask8(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);

    if(!insn)
        return 0;

    // Find the start of the function
    uint16_t* fn_start = find_last_insn_matching(region, kdata, ksize, insn, insn_is_preamble_push);
    if(!fn_start)
        return 0;

    return ((uintptr_t)fn_start | 1) - ((uintptr_t)kdata);
}

// Utility function, necessary for the sandbox hook.
uint32_t find_memcmp8(uint32_t region, uint8_t* kdata, size_t ksize)
{
    // Okay, search is actually the entire text of memcmp. This is in order to distinguish it from bcmp. However, memcmp is the same as bcmp if you only care about equality.
    const struct find_search_mask search_masks[] =
    {
        {0xFD00, 0xB100},
        {0xFFF0, 0xF890},
        {0x0000, 0x0000},
        {0xF800, 0x7800},
        {0xFF00, 0x4500},
        {0xFF00, 0xBF00},
        {0xFFF0, 0xEBA0},
        {0x8030, 0x0000},
        {0xFFFF, 0x4770},
        {0xF8FF, 0x3801},
        {0xFFF0, 0xF100},
        {0xF0FF, 0x0001},
        {0xFFF0, 0xF100},
        {0xF0FF, 0x0001},
        {0xFF00, 0xD100},
        {0xF8FF, 0x2000},
        {0xFFFF, 0x4770}
    };

    uint16_t* ptr = find_with_search_mask8(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!ptr)
        return 0;

    return ((uintptr_t)ptr | 1) - ((uintptr_t)kdata);
}

// Dereference this, add 0x38 to the resulting pointer, and write whatever boot-args are suitable to affect kern.bootargs.
uint32_t find_p_bootargs8(uint32_t region, uint8_t* kdata, size_t ksize)
{
    // Find location of the "BBBBBBBBGGGGGGGGRRRRRRRR" string.
    uint8_t* pixel_format = memmem(kdata, ksize, "BBBBBBBBGGGGGGGGRRRRRRRR", sizeof("BBBBBBBBGGGGGGGGRRRRRRRR"));
    if(!pixel_format)
        return 0;

    // Find a reference to the "BBBBBBBBGGGGGGGGRRRRRRRR" string.
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)pixel_format - (uintptr_t)kdata);
    if(!ref)
        return 0;

    // Find the beginning of the function
    uint16_t* fn_start = find_last_insn_matching(region, kdata, ksize, ref, insn_is_preamble_push);
    if(!fn_start)
        return 0;

    // Find the first MOV Rx, #1. This is to eventually set PE_state as initialized
    int found = 0;
    uint16_t* current_instruction = fn_start;
    while((uintptr_t)current_instruction < (uintptr_t)ref)
    {
        if(insn_is_mov_imm(current_instruction) && insn_mov_imm_imm(current_instruction) == 1)
        {
            found = 1;
            break;
        }

        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }

    if(!found)
        return 0;

    // This finds the STR Rx, [Ry] instrunction following that actually writes the #1. We will use Ry to find PE_state.
    found = 0;
    current_instruction += 2;
    uint32_t str_val = insn_str_imm_imm(current_instruction);
    current_instruction += 2;
    
    // Now find the location of PE_state
    uint32_t pe_state = find_pc_rel_value(region, kdata, ksize, current_instruction, insn_str_imm_rn(current_instruction)) + str_val;

    if(!pe_state)
        return 0;

    // p_boot_args is 0x70 offset in that struct.
    return pe_state + 0x70;
}

uint32_t find_mount8(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const struct find_search_mask search_masks[] =
    {
        {0xFFF0, 0xF420},
        {0xF0FF, 0x3080},
        {0xFFF0, 0xF010},
        {0xFFFF, 0x0F20},
        {0xFFFF, 0xBF08},
        {0xFFF0, 0xF440},
        {0xF0FF, 0x3080},
        {0xFFF0, 0xF010},
        {0xFFFF, 0x0F01}
    };

    uint16_t* insn = find_with_search_mask8(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!insn)
        return 0;

    insn -= 1;

    return ((uintptr_t)insn) - ((uintptr_t)kdata);
}

// NOP out the BL call here.
uint32_t find_sandbox_call_i_can_has_debugger8(uint32_t region, uint8_t* kdata, size_t ksize)
{
    
    const struct find_search_mask search_masks_90[] =
    {
        {0xFFFF, 0xB590}, // PUSH {R4,R7,LR}
        {0xFFFF, 0xAF01}, // ADD  R7, SP, #4
        {0xFFFF, 0x2000}, // MOVS R0, #0
        {0xFFFF, 0x2400}, // MOVS R4, #0
        {0xF800, 0xF000}, // BL   i_can_has_debugger
        {0xD000, 0xD000},
        {0xFD07, 0xB100}  // CBZ  R0, loc_xxx
    };
    
    const struct find_search_mask search_masks[] =
    {
        {0xFFFF, 0xB590}, // PUSH {R4,R7,LR}
        {0xFFFF, 0x2000}, // MOVS R0, #0
        {0xFFFF, 0xAF01}, // ADD  R7, SP, #4
        {0xFFFF, 0x2400}, // MOVS R4, #0
        {0xF800, 0xF000}, // BL   i_can_has_debugger
        {0xD000, 0xD000},
        {0xFD07, 0xB100}  // CBZ  R0, loc_xxx
    };

    uint16_t* ptr = find_with_search_mask8(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!ptr)
        ptr = find_with_search_mask8(region, kdata, ksize, sizeof(search_masks_90) / sizeof(*search_masks_90), search_masks_90);
    if(!ptr)
        return 0;

    return (uintptr_t)ptr + 8 - ((uintptr_t)kdata);
}

// This gets the zone_page_table array in osfmk/kern/zalloc.c. Useful for diagnosing problems with the zone allocator.
uint32_t find_zone_page_table8(uint32_t region, uint8_t* kdata, size_t ksize)
{
    // Find location of a panic string used by the zone_page_table_expand function.
    uint8_t* zone_page_table_expand = memmem(kdata, ksize, "\"zone_page_table_expand\"", sizeof("\"zone_page_table_expand\""));
    if(!zone_page_table_expand)
        return 0;

    // Find a reference to the panic string
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)zone_page_table_expand - (uintptr_t)kdata);
    if(!ref)
        return 0;

    // Find the beginning of the function
    uint16_t* fn_start = find_last_insn_matching(region, kdata, ksize, ref, insn_is_preamble_push);
    if(!fn_start)
        return 0;

    // Find the instruction that performs the first level page table translation: LDR Rt, [Rn, Rm, LSL#2]. Rn is the address of zone_page_table
    int found = 0;
    uint16_t* current_instruction = fn_start;
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_ldr_reg(current_instruction) && insn_ldr_reg_lsl(current_instruction) == 2)
        {
            found = 1;
            break;
        }

        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }

    if(!found)
        return 0;

    return find_pc_rel_value(region, kdata, ksize, current_instruction, insn_ldr_reg_rn(current_instruction));
}

// Function to free leaked ipc_kmsg objects
uint32_t find_ipc_kmsg_destroy8(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const uint8_t search[] = {0x75, 0x68, 0x06, 0x60, 0x45, 0x60, 0x70, 0x60, 0x28, 0x60, 0xF0, 0xBD};
    void* ptr = memmem(kdata, ksize, search, sizeof(search));
    if(!ptr)
        return 0;

    uint16_t* fn_start = find_last_insn_matching(region, kdata, ksize, (uint16_t*)ptr, insn_is_preamble_push);
    return ((uintptr_t)fn_start - (uintptr_t)kdata) | 1;
}

// Function used to free any dead ports we find to clean up after memory leak.
uint32_t find_io_free8(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const uint8_t search[] = {0xB0, 0xB5, 0x05, 0x46, 0x0C, 0x46, 0x02, 0xAF, 0x15, 0xB9};
    void* ptr = memmem(kdata, ksize, search, sizeof(search));
    if(!ptr)
        return 0;

    return (((uintptr_t)ptr) - ((uintptr_t)kdata)) | 1;
}

uint32_t find_proc_enforce8(uint32_t region, uint8_t* kdata, size_t ksize)
{
    // Find the description.
    uint8_t* proc_enforce_description = memmem(kdata, ksize, "Enforce MAC policy on process operations", sizeof("Enforce MAC policy on process operations"));
    if(!proc_enforce_description)
        return 0;

    // Find what references the description.
    uint32_t proc_enforce_description_address = region + ((uintptr_t)proc_enforce_description - (uintptr_t)kdata);
    uint8_t* proc_enforce_description_ptr = memmem(kdata, ksize, &proc_enforce_description_address, sizeof(proc_enforce_description_address));
    if(!proc_enforce_description_ptr)
        return 0;

    // Go up the struct to find the pointer to the actual data element.
    uint32_t* proc_enforce_ptr = (uint32_t*)(proc_enforce_description_ptr - (5 * sizeof(uint32_t)));
    return *proc_enforce_ptr - region;
}

// Search the range of kdata for a series of 16-bit values that match the search mask.
static uint16_t* find_with_search_mask(uint32_t region, uint8_t* kdata, size_t ksize, int num_masks, const struct find_search_mask* masks)
{
    uint16_t* end = (uint16_t*)(kdata + ksize - (num_masks * sizeof(uint16_t)));
    uint16_t* cur;
    for(cur = (uint16_t*) kdata; cur <= end; ++cur)
    {
        int matched = 1;
        int i;
        for(i = 0; i < num_masks; ++i)
        {
            if((*(cur + i) & masks[i].mask) != masks[i].value)
            {
                matched = 0;
                break;
            }
        }

        if(matched)
            return cur;
    }

    return NULL;
}

uint32_t find_vm_map_enter_patch8(uint32_t region, uint8_t* kdata, size_t ksize)
{
    
    const struct find_search_mask search_masks_90[] =
    {
        {0xFFF0, 0xF010}, // TST.W Rz, #4
        {0xFFFF, 0x0F04},
        {0xFF78, 0x4600}, // MOV Rx, R0 (?)
        {0xFFF0, 0xBF10}, // IT NE (?)
        {0xFFF0, 0xF020}, // BICNE.W         Rk, Rk, #4
        {0xF0FF, 0x0004}
    };
    
    const struct find_search_mask search_masks_84[] =
    {
        {0xFFF0, 0xF000}, // AND.W Rx, Ry, #2
        {0xF0FF, 0x0002},
        {0xFFF0, 0xF010}, // TST.W Rz, #2
        {0xFFFF, 0x0F02},
        {0xFF00, 0xD000}, // BEQ   loc_xxx
        {0xF8FF, 0x2000}, // MOVS  Rk, #0
        {0xFFF0, 0xF010}, // TST.W Rz, #4
        {0xFFFF, 0x0F04}
    };

    const struct find_search_mask search_masks[] =
    {
        {0xFBE0, 0xF000},
        {0x8000, 0x0000},
        {0xFFF0, 0xF010},
        {0xFFFF, 0x0F02},
        {0xFF00, 0xD000},
        {0xF8FF, 0x2000},
        {0xFFF0, 0xF010},
        {0xFFFF, 0x0F04}
    };

    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_84) / sizeof(*search_masks_84), search_masks_84);
    if(!insn)
        insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!insn){
        insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_90) / sizeof(*search_masks_90), search_masks_90);
        if(!insn)
            return 0;
        insn += 4;
        return ((uintptr_t)insn) - ((uintptr_t)kdata);
    }
    
        insn += 2;
        
        return ((uintptr_t)insn) - ((uintptr_t)kdata);
}

// NOP out the BICNE.W instruction with 4 here.
uint32_t find_vm_map_protect_patch8(uint32_t region, uint8_t* kdata, size_t ksize)
{
    
    const struct find_search_mask search_masks_90[] =
    {
        {0xFBF0, 0xF010}, // TST.W   Rx, #0x20000000
        {0x8F00, 0x0F00},
        {0xFFC0, 0x6840}, // LDR     Rz, [Ry,#4]
        {0xFFF0, 0xF000}, // AND.W   Ry, Rk, #6
        {0xF0FF, 0x0006},
        {0xFFC0, 0x68C0}, // LDR     Rs, [Ry,#0xC]
        {0xFF00, 0x4600}, // MOV     Rx, Ry (?)
        {0xFFF0, 0xBF00}, // IT      EQ (?)
        {0xFFF0, 0xF020}, // BICNE.W Rk, Rk, #4
        {0xF0FF, 0x0004}
        //{0xF8FF, 0x2806}, // CMP     Ry, #6
        //{0xFFF0, 0xBF00}, // IT      EQ
    };
    
    const struct find_search_mask search_masks_84[] =
    {
        {0xFBF0, 0xF010}, // TST.W Rx, #0x20000000
        {0x8F00, 0x0F00},
        {0xFBFF, 0xF04F}, // MOV.W Rx, #0
        {0x8000, 0x0000},
        {0xFFF0, 0xBF00}, // IT EQ
        {0xF8FF, 0x2001}, // MOVEQ Rx, #1
        {0xFFC0, 0x6840}, // LDR             Rz, [Ry,#4]
        {0xFFC0, 0x68C0}, // LDR             Rs, [Ry,#0xC]
        {0xFFF0, 0xF000}, // AND.W           Ry, Rk, #6
        {0xF0FF, 0x0006},
        {0xF8FF, 0x2806}, // CMP             Ry, #6
        {0xFBFF, 0xF04F}, // MOV.W           Ry, #0
        {0x8000, 0x0000},
        {0xFFF0, 0xBF00}, // IT EQ (?)
        {0xF8FF, 0x2001}, // MOVEQ           Ry, #1
        {0xFFC0, 0x4200}, // TST             Ry, Rx
        {0xFFF0, 0xBF10}, // IT NE (?)
        {0xFFF0, 0xF020}, // BICNE.W         Rk, Rk, #4
        {0xF0FF, 0x0004}
    };

    const struct find_search_mask search_masks[] =
    {
        {0xFBF0, 0xF010},
        {0x8F00, 0x0F00},
        {0xFBFF, 0xF04F},
        {0x8000, 0x0000},
        {0xFFF0, 0xF000},
        {0xF0FF, 0x0006},
        {0xFFF0, 0xBF00},
        {0xF8FF, 0x2001},
        {0xF8FF, 0x2806},
        {0xFBFF, 0xF04F},
        {0x8000, 0x0000},
        {0xFFF0, 0xBF00},
        {0xF8FF, 0x2001},
        {0xFFC0, 0x4200},
        {0xFFF0, 0xBF10},
        {0xFFF0, 0xF020},
        {0xF0FF, 0x0004}
    };

    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_84) / sizeof(*search_masks_84), search_masks_84);
    if(!insn) {
        insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
        if(!insn) {
            insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_90) / sizeof(*search_masks_90), search_masks_90);
            if(!insn)
                return 0;
            insn += 8;
        }
        else
            insn += 15;
    } else
        insn += 17;

    return ((uintptr_t)insn) - ((uintptr_t)kdata);
}

uint32_t find_vm_fault_enter_patch_84(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const struct find_search_mask search_masks_a5[] =
    {
        // A5(x&rA)
        {0xF0F0, 0xF000}, // AND.W Rx, Ry, #0x40
        {0xF0FF, 0x0040}, //
        {0xFFF0, 0xF8D0}, // ldr.w x, [Ry, #z]
        {0x0000, 0x0000},
        {0xFFF0, 0xF8D0}, // ldr.w x, [Ry, #z]
        {0x0000, 0x0000},
        {0xFBF0, 0xF010}, // TST.W Rx, #0x200000
        {0x0F00, 0x0F00},
        {0xFF00, 0xD100}, // BNE x              <- NOP
        {0xF800, 0x6800}, // LDR R2, [Ry,#X]    <- movs r2, #1
        
    };
    
    const struct find_search_mask search_masks_a6[] =
    {
        // A6
        {0xFFF0, 0xF8D0}, // ldr.w x, [Ry, #z]
        {0x0000, 0x0000},
        {0xF0F0, 0xF000}, // AND.W Rx, Ry, #0x40
        {0xF0FF, 0x0040}, //
        {0xFBF0, 0xF010}, // TST.W Rx, #0x200000
        {0x0F00, 0x0F00},
        {0xF800, 0x6800}, // LDR R3, [Ry,#X]
        {0xFF00, 0xD100}, // BNE x              <- NOP
        {0xF800, 0x6800}, // LDR R2, [Ry,#X]    <- movs r2, #1
        
    };
    
    uint16_t* insn_a6 = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_a6) / sizeof(*search_masks_a6), search_masks_a6);
    
    if(!insn_a6){
        uint16_t* insn_a5 = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_a5) / sizeof(*search_masks_a5), search_masks_a5);
        if(!insn_a5){
            return 0;
        }
        return ((uintptr_t)insn_a5) - ((uintptr_t)kdata)+16;
    } else {
        return ((uintptr_t)insn_a6) - ((uintptr_t)kdata)+14;
    }
    
    return 0;
}

// Replace with NOP
uint32_t find_csops8(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const struct find_search_mask search_masks_90[] =
    {
        {0xFFF0, 0xF100},
        {0x0000, 0x0000},
        {0xFF80, 0x4600},
        {0xFC00, 0xF400},
        {0x0000, 0x0000},
        {0xFFF0, 0xF890},
        {0x0000, 0x0000},
        {0xFFF0, 0xF010},
        {0xFFFF, 0x0F01},
        {0xF800, 0xD000},
    };
    
    const struct find_search_mask search_masks[] =
    {
        {0xFC00, 0xF400},
        {0x0000, 0x0000},
        {0xF800, 0xE000},
        {0x0000, 0x0000},
        {0xFFF0, 0xF100},
        {0x0000, 0x0000},
        {0xFF80, 0x4600},
        {0xF800, 0xF000},
        {0x0000, 0x0000},
        {0xFF80, 0x4600},
        {0xFFF0, 0xF890},
        {0x0000, 0x0000},
        {0xFFF0, 0xF010},
        {0xFFFF, 0x0F01},
        {0xFC00, 0xF000},
        {0x0000, 0x0000}
    };

    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!insn) {
        insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_90) / sizeof(*search_masks_90), search_masks_90);
        if(!insn)
            return 0;
        insn += 9;
    }
    else
        insn += 14;

    return ((uintptr_t)insn) - ((uintptr_t)kdata);
}

// Set 0x20 here. Replace
uint32_t find_csops2(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const struct find_search_mask search_masks[] =
    {
        {0xF800, 0x9800},
        {0xFBF0, 0xF100},
        {0x8000, 0x0000},
        {0xFFC0, 0x4600},
        {0xF800, 0xF000},
        {0xF800, 0xE800},
        {0xFFF0, 0xF8D0},
        {0x0000, 0x0000},
        {0xFAF0, 0xF040}
    };

    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!insn)
        return 0;

    insn += 8;

    return ((uintptr_t)insn) - ((uintptr_t)kdata);
}
