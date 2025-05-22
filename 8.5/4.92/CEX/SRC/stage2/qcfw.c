#include <lv2/lv2.h>
#include <lv2/libc.h>
#include <lv2/security.h>
#include <lv2/patch.h>
#include <lv2/symbols.h>
#include <lv2/thread.h>
#include <lv2/time.h>
#include <lv2/process.h>
#include <lv2/memory.h>

#include "common.h"
#include "qcfw.h"

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

    if (!isNpdrm)
    {
        DPRINTF("Not npdrm\n");
        return;
    }

    DPRINTF("npdrm detected!\n");
    timer_usleep(MILISECONDS(1200)); // weird hang fix
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
    // 4.92 CEX
    do_patch32(MKA(0x59dc4), 0x38600000);
}

void qcfw_patch_vsh(process_t vsh_process)
{
    // 4.92 CEX

    uint64_t patch64;
    uint32_t patch32;

    patch64 = 0x386000004e800020;
    patch32 = 0x38600000;
    process_write_memory(vsh_process, (void *)0x253250, &patch64, 8, 1);
    process_write_memory(vsh_process, (void *)0x252020, &patch64, 8, 1); // only on hen cause theres a check on signature of rif that R and S cant be completly 0. this patches that.
    process_write_memory(vsh_process, (void *)0x255910, &patch32, 4, 1);
    process_write_memory(vsh_process, (void *)0x255af0, &patch32, 4, 1);
    patch32 = 0x60000000;
    process_write_memory(vsh_process, (void *)0x255f68, &patch32, 4, 1);
    patch32 = 0x38600000;
    process_write_memory(vsh_process, (void *)0x2563d0, &patch32, 4, 1);
    process_write_memory(vsh_process, (void *)0x256970, &patch32, 4, 1);
    process_write_memory(vsh_process, (void *)0x5f4c6c, &patch64, 8, 1);
    patch64 = 0x386000014e800020;
    process_write_memory(vsh_process, (void *)0x5fc634, &patch64, 8, 1);

    // weird cbomb fix?

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
}
