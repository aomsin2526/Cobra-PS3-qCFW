#include <lv1/lv1.h>
#include <lv1/lv1call.h>

#include <lv2/lv2.h>
#include <lv2/libc.h>
#include <lv2/security.h>
#include <lv2/patch.h>
#include <lv2/symbols.h>
#include <lv2/thread.h>
#include <lv2/time.h>
#include <lv2/process.h>
#include <lv2/memory.h>
#include <lv2/ctrl.h>

#include "common.h"
#include "qcfw.h"

uint8_t qcfw_is_loadusb = 0;

void qcfw_dead()
{
    while (1)
    {
    }
}

struct qcfw_appldr_subargs_s
{
    uint64_t program_auth_id;
    uint64_t self_header_addr;
    uint64_t program_segment_addr;

    uint32_t segment_type;
    uint32_t program_segment_index;

    uint64_t destination_addr;
    uint64_t capability_addr;

    uint64_t flag;

    uint64_t junk0[5];

    uint64_t sceNpDrmKey[2];

    uint64_t header_key_check_result_addr;

    uint64_t junk1;
};

void qcfw_print_appldr_subargs(struct qcfw_appldr_subargs_s* subargs)
{
    DPRINTF("qcfw_print_appldr_subargs()\n");

	DPRINTF("program_auth_id = 0x%lx\n", subargs->program_auth_id);
	DPRINTF("self_header_addr = 0x%lx\n", subargs->self_header_addr);
	DPRINTF("program_segment_addr = 0x%lx\n", subargs->program_segment_addr);

	DPRINTF("segment_type = 0x%x\n", subargs->segment_type);
	DPRINTF("program_segment_index = 0x%x\n", subargs->program_segment_index);

	DPRINTF("destination_addr = 0x%lx\n", subargs->destination_addr);
	DPRINTF("capability_addr = 0x%lx\n", subargs->capability_addr);

	DPRINTF("flag = 0x%lx\n", subargs->flag);

	DPRINTF("sceNpDrmKey[0] = 0x%lx\n", subargs->sceNpDrmKey[0]);
	DPRINTF("sceNpDrmKey[1] = 0x%lx\n", subargs->sceNpDrmKey[1]);

	DPRINTF("header_key_check_result_addr = 0x%lx\n", subargs->header_key_check_result_addr);
}

struct SceHeader_s
{
    uint32_t magic;
    uint32_t version;
    uint16_t attribute;
    uint16_t category;
    uint32_t ext_header_size;
    uint64_t file_offset;
    uint64_t file_size;
};

struct SceProgramIdentHeader_s
{
    uint64_t program_authority_id;
    uint32_t program_vender_id;
    uint32_t program_type;
    uint64_t program_sceversion;
    uint64_t padding;
};

void qcfw_post_hvcall_99(uint64_t *spu_obj, uint64_t *spu_args)
{
    if (!qcfw_is_loadusb)
        return;

    DPRINTF("qcfw_post_hvcall_99()\n");

    struct qcfw_appldr_subargs_s *subargs = (struct qcfw_appldr_subargs_s *)spu_args;
    qcfw_print_appldr_subargs(subargs);

    if (subargs->program_auth_id == 0)
    {
        DPRINTF("program_auth_id must not 0\n");
        return;
    }

    uint64_t self_header_addr = subargs->self_header_addr;

    struct SceHeader_s *sceHeader = (struct SceHeader_s *)self_header_addr;

    if (sceHeader->magic != 0x53434500)
    {
        DPRINTF("magic check failed!\n");
        return;
    }

    if (sceHeader->category != 1)
    {
        DPRINTF("Not self/sprx\n");
        return;
    }

    struct SceProgramIdentHeader_s *sceProgramIdentHeader = (struct SceProgramIdentHeader_s *)(self_header_addr + 0x70);
    uint8_t isNpdrm = (sceProgramIdentHeader->program_type == 8) ? 1 : 0;

    DPRINTF("sceHeader->attribute = 0x%x\n", (uint32_t)sceHeader->attribute);

    DPRINTF("sceProgramIdentHeader->program_type = 0x%x\n", (uint32_t)sceProgramIdentHeader->program_type);
    DPRINTF("sceProgramIdentHeader->program_authority_id = 0x%lx\n", sceProgramIdentHeader->program_authority_id);

    uint8_t isCustomVshModules = ((sceProgramIdentHeader->program_authority_id == 0x1070000052000001) && (sceHeader->attribute < 0x1C)) ? 1 : 0;

    uint8_t isRetailNonNpdrm = ((sceProgramIdentHeader->program_authority_id == 0x1010000001000003) && (sceProgramIdentHeader->program_type == 4)) ? 1 : 0;

    uint8_t doWait = 0;

    if (!isNpdrm)
        DPRINTF("Not npdrm\n");
    else
    {
        DPRINTF("npdrm detected!\n");
        doWait = 1;
    }

    if (!isCustomVshModules)
        DPRINTF("Not custom vsh modules\n");
    else
    {
        DPRINTF("Custom vsh modules detected!\n");
        doWait = 1;
    }

    if (!isRetailNonNpdrm)
        DPRINTF("Not isRetailNonNpdrm\n");
    else
    {
        DPRINTF("isRetailNonNpdrm detected!\n");
        doWait = 1;
    }

    if (!doWait)
        return;

    timer_usleep(MILISECONDS(1200)); // weird hang fix
}

void qcfw_patch_vsh(process_t vsh_process)
{
    DPRINTF("qcfw_patch_vsh()\n");

    // 4.92 CEX

    uint64_t patch64;
    uint32_t patch32;

    // cbomb fix

    // 0x80010601

    patch64 = 0x3800000038600000;
    process_write_memory(vsh_process, (void *)(0x252B10), &patch64, 8, 1);

    patch64 = 0x419E00543C8000DC;
    process_write_memory(vsh_process, (void *)(0x252B10 + 8), &patch64, 8, 1);

    patch64 = 0x480000703D408001;
    process_write_memory(vsh_process, (void *)(0x5D3D90), &patch64, 8, 1);

    patch64 = 0x3940000048000018;
    process_write_memory(vsh_process, (void *)(0x5D3D90 + 8), &patch64, 8, 1);

    // 0x8002951E

    patch64 = 0x3860000041980008;
    process_write_memory(vsh_process, (void *)(0x252B60), &patch64, 8, 1);

    patch64 = 0x38600000E80100A0;
    process_write_memory(vsh_process, (void *)(0x252B60 + 8), &patch64, 8, 1);

    // default timestamp

    patch64 = 0x3C0000E26000CABE;
    process_write_memory(vsh_process, (void *)(0x5D3DB4), &patch64, 8, 1);

    patch64 = 0x780007C66400CEE0;
    process_write_memory(vsh_process, (void *)(0x5D3DB4 + 8), &patch64, 8, 1);

    patch64 = 0x60002000F81F0000;
    process_write_memory(vsh_process, (void *)(0x5D3DC4), &patch64, 8, 1);

    patch64 = 0x480000403C00000F;
    process_write_memory(vsh_process, (void *)(0x5D3DC4 + 8), &patch64, 8, 1);

    // psn firmware version check bypass

    patch32 = 0x38000082;
    process_write_memory(vsh_process, (void *)(0x2455EC), &patch32, 4, 1);
}

void qcfw_patch_ps3swu(process_t process)
{
    DPRINTF("qcfw_patch_ps3swu()\n");

    sm_ring_buzzer(SINGLE_BEEP);

    // NoBD/NoBT
    //process_write_memory(process, (void *)(0x5A9B4), patches, sizeof(patches), 1);

    // 3C 00 80 02 60 00 F0 00 7F 9E 00 00 41 9E 00 1C
    // ->
    // 3C 00 80 02 60 00 F0 00 7F 80 00 00 41 9E 00 1C

    uint8_t scan[16] =    { 0x3C, 0x00, 0x80, 0x02, 0x60, 0x00, 0xF0, 0x00, 0x7F, 0x9E, 0x00, 0x00, 0x41, 0x9E, 0x00, 0x1C };
    uint8_t replace[16] = { 0x3C, 0x00, 0x80, 0x02, 0x60, 0x00, 0xF0, 0x00, 0x7F, 0x80, 0x00, 0x00, 0x41, 0x9E, 0x00, 0x1C };

    // 0x10000, 0x300000

    for (uint64_t addr = 0x10000; addr < 0x300000; addr += 4)
    {
        uint8_t mem[16] = {0};
        
        process_read_memory(process, (void*)addr, mem, 16);

        //uint32_t* xxx = (uint32_t*)mem;
        //DPRINTF("addr = 0x%lx, xxx = 0x%x\n", addr, *xxx);

        if (!memcmp(mem, scan, 16))
        {
            process_write_memory(process, (void*)(addr), replace, sizeof(replace), 1);

            timer_usleep(MILISECONDS(1000));
            sm_ring_buzzer(DOUBLE_BEEP);
            timer_usleep(MILISECONDS(1000));
            sm_ring_buzzer(DOUBLE_BEEP);
            timer_usleep(MILISECONDS(1000));
            sm_ring_buzzer(DOUBLE_BEEP);

            break;
        }
    }
}

uint8_t post_send_and_receive_with_auth_id_is_in_loop = 0;

LV2_HOOKED_FUNCTION_PRECALL_2(int32_t, post_send_and_receive_with_auth_id, (uint32_t* a1, uint64_t a2))
{
    if (!post_send_and_receive_with_auth_id_is_in_loop)
    {
        if (a1[6] == 0xf)
        {
            post_send_and_receive_with_auth_id_is_in_loop = 1;
            call_hooked_function_2(post_send_and_receive_with_auth_id, a1, a2);
            post_send_and_receive_with_auth_id_is_in_loop = 0;
        }
    }

    return 0;
}

void do_patch(uint64_t addr, uint64_t patch)
{
    *(uint64_t *)addr = patch;
    clear_icache((void *)addr, 8);
}

void do_patch32(uint64_t addr, uint32_t patch)
{
    *(uint32_t *)addr = patch;
    clear_icache((void *)addr, 4);
}

void qcfw_init()
{
    DPRINTF("qcfw_init()\n");

    qcfw_is_loadusb = (*((volatile uint8_t*)(0x8000000000000030)) == 1);

    if (qcfw_is_loadusb)
        DPRINTF("qcfw_is_loadusb\n");

    hook_function_with_precall(0x212F7C, post_send_and_receive_with_auth_id, 2);

    // ecdsa
    do_patch32(MKA(0x59dc4), 0x38600000);

    // spoof ps2 bc flags
    {
        DPRINTF("Spoofing ps2 bc flags\n");

        int32_t res = 99;

        uint8_t config[8];
        uint64_t v2;

        res = lv1_get_repository_node_value(PS3_LPAR_ID_PME, FIELD_FIRST("sys", 0), FIELD("hw", 0), FIELD("config", 0), 0, (uint64_t *)config, &v2);
        DPRINTF("res = 0x%x\n", res);

        DPRINTF("old sys.hw.config = 0x%lx\n", *(uint64_t*)config);
        config[6] |= 1;
        DPRINTF("new sys.hw.config = 0x%lx\n", *(uint64_t*)config);

        res = lv1_modify_repository_node_value(PS3_LPAR_ID_PME, FIELD_FIRST("sys", 0), FIELD("hw", 0), FIELD("config", 0), 0, *(uint64_t*)config, v2);
        DPRINTF("res = 0x%x\n", res);
    }
}
