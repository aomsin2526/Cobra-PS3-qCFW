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

void qcfw_dead()
{
    while (1)
    {
    }
}

void qcfw_init()
{
    DPRINTF("qcfw_init()\n");

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
