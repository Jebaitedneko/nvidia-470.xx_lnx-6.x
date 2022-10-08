/*******************************************************************************
    Copyright (c) 2015-2020 NVIDIA Corporation

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to
    deal in the Software without restriction, including without limitation the
    rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
    sell copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

        The above copyright notice and this permission notice shall be
        included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.

*******************************************************************************/

#include "uvm_channel.h"
#include "uvm_global.h"
#include "uvm_hal.h"
#include "uvm_pmm_gpu.h"
#include "uvm_push.h"
#include "uvm_test.h"
#include "uvm_tracker.h"
#include "uvm_va_space.h"
#include "uvm_rm_mem.h"
#include "uvm_mem.h"

#define CE_TEST_MEM_SIZE (2 * 1024 * 1024)
#define CE_TEST_MEM_END_SIZE 32
#define CE_TEST_MEM_BEGIN_SIZE 32
#define CE_TEST_MEM_MIDDLE_SIZE (CE_TEST_MEM_SIZE - CE_TEST_MEM_BEGIN_SIZE - CE_TEST_MEM_END_SIZE)
#define CE_TEST_MEM_MIDDLE_OFFSET (CE_TEST_MEM_BEGIN_SIZE)
#define CE_TEST_MEM_END_OFFSET (CE_TEST_MEM_SIZE - CE_TEST_MEM_BEGIN_SIZE)
#define CE_TEST_MEM_COUNT 5

static NV_STATUS test_non_pipelined(uvm_gpu_t *gpu)
{
    NvU32 i;
    NV_STATUS status;
    uvm_rm_mem_t *mem[CE_TEST_MEM_COUNT] = { NULL };
    uvm_rm_mem_t *host_mem = NULL;
    NvU32 *host_ptr;
    NvU64 host_mem_gpu_va;
    NvU64 dst_va;
    NvU64 src_va;
    uvm_push_t push;

    status = uvm_rm_mem_alloc_and_map_cpu(gpu, UVM_RM_MEM_TYPE_SYS, CE_TEST_MEM_SIZE, &host_mem);
    TEST_CHECK_GOTO(status == NV_OK, done);
    host_ptr = (NvU32 *)uvm_rm_mem_get_cpu_va(host_mem);
    host_mem_gpu_va = uvm_rm_mem_get_gpu_va(host_mem, gpu);
    memset(host_ptr, 0, CE_TEST_MEM_SIZE);

    for (i = 0; i < CE_TEST_MEM_COUNT; ++i) {
        status = uvm_rm_mem_alloc(gpu, UVM_RM_MEM_TYPE_GPU, CE_TEST_MEM_SIZE, &mem[i]);
        TEST_CHECK_GOTO(status == NV_OK, done);
    }

    status = uvm_push_begin(gpu->channel_manager, UVM_CHANNEL_TYPE_GPU_INTERNAL, &push, "Non-pipelined test");
    TEST_CHECK_GOTO(status == NV_OK, done);

    // All of the following CE transfers are done from a single (L)CE and
    // disabling pipelining is enough to order them when needed. Only push_end
    // needs a MEMBAR SYS to order everything with the CPU.

    // Initialize to a bad value
    for (i = 0; i < CE_TEST_MEM_COUNT; ++i) {
        uvm_push_set_flag(&push, UVM_PUSH_FLAG_CE_NEXT_PIPELINED);
        uvm_push_set_flag(&push, UVM_PUSH_FLAG_CE_NEXT_MEMBAR_NONE);
        gpu->parent->ce_hal->memset_v_4(&push, uvm_rm_mem_get_gpu_va(mem[i], gpu), 1337 + i, CE_TEST_MEM_SIZE);
    }

    // Set the first buffer to 1
    uvm_push_set_flag(&push, UVM_PUSH_FLAG_CE_NEXT_MEMBAR_NONE);
    gpu->parent->ce_hal->memset_v_4(&push, uvm_rm_mem_get_gpu_va(mem[0], gpu), 1, CE_TEST_MEM_SIZE);

    for (i = 0; i < CE_TEST_MEM_COUNT; ++i) {
        NvU32 dst = i + 1;
        if (dst == CE_TEST_MEM_COUNT)
            dst_va = host_mem_gpu_va;
        else
            dst_va = uvm_rm_mem_get_gpu_va(mem[dst], gpu);

        src_va = uvm_rm_mem_get_gpu_va(mem[i], gpu);

        // The first memcpy needs to be non-pipelined as otherwise the previous
        // memset/memcpy to the source may not be done yet.

        // Alternate the order of copying the beginning and the end
        if (i % 2 == 0) {
            uvm_push_set_flag(&push, UVM_PUSH_FLAG_CE_NEXT_MEMBAR_NONE);
            gpu->parent->ce_hal->memcopy_v_to_v(&push, dst_va + CE_TEST_MEM_END_OFFSET, src_va + CE_TEST_MEM_END_OFFSET, CE_TEST_MEM_END_SIZE);

            uvm_push_set_flag(&push, UVM_PUSH_FLAG_CE_NEXT_MEMBAR_NONE);
            uvm_push_set_flag(&push, UVM_PUSH_FLAG_CE_NEXT_PIPELINED);
            gpu->parent->ce_hal->memcopy_v_to_v(&push,
                                               dst_va + CE_TEST_MEM_MIDDLE_OFFSET,
                                               src_va + CE_TEST_MEM_MIDDLE_OFFSET,
                                               CE_TEST_MEM_MIDDLE_SIZE);

            uvm_push_set_flag(&push, UVM_PUSH_FLAG_CE_NEXT_MEMBAR_NONE);
            uvm_push_set_flag(&push, UVM_PUSH_FLAG_CE_NEXT_PIPELINED);
            gpu->parent->ce_hal->memcopy_v_to_v(&push, dst_va, src_va, CE_TEST_MEM_BEGIN_SIZE);
        }
        else {
            uvm_push_set_flag(&push, UVM_PUSH_FLAG_CE_NEXT_MEMBAR_NONE);
            gpu->parent->ce_hal->memcopy_v_to_v(&push, dst_va, src_va, CE_TEST_MEM_BEGIN_SIZE);

            uvm_push_set_flag(&push, UVM_PUSH_FLAG_CE_NEXT_MEMBAR_NONE);
            uvm_push_set_flag(&push, UVM_PUSH_FLAG_CE_NEXT_PIPELINED);
            gpu->parent->ce_hal->memcopy_v_to_v(&push,
                                               dst_va + CE_TEST_MEM_MIDDLE_OFFSET,
                                               src_va + CE_TEST_MEM_MIDDLE_OFFSET,
                                               CE_TEST_MEM_MIDDLE_SIZE);

            uvm_push_set_flag(&push, UVM_PUSH_FLAG_CE_NEXT_MEMBAR_NONE);
            uvm_push_set_flag(&push, UVM_PUSH_FLAG_CE_NEXT_PIPELINED);
            gpu->parent->ce_hal->memcopy_v_to_v(&push,
                                               dst_va + CE_TEST_MEM_END_OFFSET,
                                               src_va + CE_TEST_MEM_END_OFFSET,
                                               CE_TEST_MEM_END_SIZE);
        }
    }

    status = uvm_push_end_and_wait(&push);
    TEST_CHECK_GOTO(status == NV_OK, done);


    for (i = 0; i < CE_TEST_MEM_SIZE / sizeof(NvU32); ++i) {
        if (host_ptr[i] != 1) {
            UVM_TEST_PRINT("host_ptr[%u] = %u instead of 1\n", i, host_ptr[i]);
            status = NV_ERR_INVALID_STATE;
            goto done;
        }
    }

done:
    for (i = 0; i < CE_TEST_MEM_COUNT; ++i) {
        uvm_rm_mem_free(mem[i]);
    }
    uvm_rm_mem_free(host_mem);

    return status;
}

#define REDUCTIONS 32

static NV_STATUS test_membar(uvm_gpu_t *gpu)
{
    NvU32 i;
    NV_STATUS status;
    uvm_rm_mem_t *host_mem = NULL;
    NvU32 *host_ptr;
    NvU64 host_mem_gpu_va;
    uvm_push_t push;
    NvU32 value;

    if (!uvm_gpu_is_gk110_plus(gpu)) {
        // semaphore_reduction_inc is only supported on GK110+
        return NV_OK;
    }

    status = uvm_rm_mem_alloc_and_map_cpu(gpu, UVM_RM_MEM_TYPE_SYS, sizeof(NvU32), &host_mem);
    TEST_CHECK_GOTO(status == NV_OK, done);
    host_ptr = (NvU32 *)uvm_rm_mem_get_cpu_va(host_mem);
    host_mem_gpu_va = uvm_rm_mem_get_gpu_va(host_mem, gpu);
    *host_ptr = 0;

    status = uvm_push_begin(gpu->channel_manager, UVM_CHANNEL_TYPE_GPU_TO_CPU, &push, "Membar test");
    TEST_CHECK_GOTO(status == NV_OK, done);

    for (i = 0; i < REDUCTIONS; ++i) {
        uvm_push_set_flag(&push, UVM_PUSH_FLAG_CE_NEXT_MEMBAR_NONE);
        gpu->parent->ce_hal->semaphore_reduction_inc(&push, host_mem_gpu_va, REDUCTIONS + 1);
    }

    // Without a sys membar the channel tracking semaphore can and does complete
    // before all the reductions.
    status = uvm_push_end_and_wait(&push);
    TEST_CHECK_GOTO(status == NV_OK, done);

    value = *host_ptr;
    if (value != REDUCTIONS) {
        UVM_TEST_PRINT("Value = %u instead of %u, GPU %s\n", value, REDUCTIONS, uvm_gpu_name(gpu));
        status = NV_ERR_INVALID_STATE;
        goto done;
    }

done:
    uvm_rm_mem_free(host_mem);

    return status;
}

static void push_memset(uvm_push_t *push, uvm_gpu_address_t dst, NvU64 value, size_t element_size, size_t size)
{
    switch (element_size) {
        case 1:
            uvm_push_get_gpu(push)->parent->ce_hal->memset_1(push, dst, (NvU8)value, size);
            break;
        case 4:
            uvm_push_get_gpu(push)->parent->ce_hal->memset_4(push, dst, (NvU32)value, size);
            break;
        case 8:
            uvm_push_get_gpu(push)->parent->ce_hal->memset_8(push, dst, value, size);
            break;
        default:
            UVM_ASSERT(0);
    }
}

static NV_STATUS test_unaligned_memset(uvm_gpu_t *gpu,
                                       uvm_gpu_address_t gpu_verif_addr,
                                       NvU8 *cpu_verif_addr,
                                       size_t size,
                                       size_t element_size,
                                       size_t offset)
{
    uvm_push_t push;
    NV_STATUS status;
    size_t i;
    NvU64 value64 = (offset + 2) * (1ull << 32) + (offset + 1);
    NvU64 test_value, expected_value = 0;
    uvm_gpu_address_t dst;

    // Copy a single element at an unaligned position and make sure it doesn't
    // clobber anything else
    TEST_CHECK_RET(gpu_verif_addr.address % element_size == 0);
    TEST_CHECK_RET(offset + element_size <= size);
    dst = gpu_verif_addr;
    dst.address += offset;

    memset(cpu_verif_addr, (NvU8)(~value64), size);

    status = uvm_push_begin(gpu->channel_manager, UVM_CHANNEL_TYPE_GPU_INTERNAL, &push,
                            "memset_%zu offset %zu",
                            element_size, offset);
    TEST_CHECK_RET(status == NV_OK);

    push_memset(&push, dst, value64, element_size, element_size);
    status = uvm_push_end_and_wait(&push);
    TEST_CHECK_RET(status == NV_OK);

    // Make sure all bytes of element are present
    test_value = 0;
    memcpy(&test_value, cpu_verif_addr + offset, element_size);

    switch (element_size) {
        case 1:
            expected_value = (NvU8)value64;
            break;
        case 4:
            expected_value = (NvU32)value64;
            break;
        case 8:
            expected_value = value64;
            break;
        default:
            UVM_ASSERT(0);
    }

    if (test_value != expected_value) {
        UVM_TEST_PRINT("memset_%zu offset %zu failed, written value is 0x%llx instead of 0x%llx\n",
                       element_size, offset, test_value, expected_value);
        return NV_ERR_INVALID_STATE;
    }

    // Make sure all other bytes are unchanged
    for (i = 0; i < size; i++) {
        if (i >= offset && i < offset + element_size)
            continue;
        if (cpu_verif_addr[i] != (NvU8)(~value64)) {
            UVM_TEST_PRINT("memset_%zu offset %zu failed, immutable byte %zu changed value from 0x%x to 0x%x\n",
                           element_size, offset, i, (NvU8)(~value64),
                           cpu_verif_addr[i]);
            return NV_ERR_INVALID_STATE;
        }
    }

    return NV_OK;
}

static NV_STATUS test_memcpy_and_memset_inner(uvm_gpu_t *gpu,
                                              uvm_gpu_address_t dst,
                                              uvm_gpu_address_t src,
                                              size_t size,
                                              size_t element_size,
                                              uvm_gpu_address_t gpu_verif_addr,
                                              void *cpu_verif_addr,
                                              int test_iteration)
{
    uvm_push_t push;
    NV_STATUS status;
    size_t i;
    const char *src_type = src.is_virtual ? "virtual" : "physical";
    const char *src_loc = src.aperture == UVM_APERTURE_SYS ? "sysmem" : "vidmem";
    const char *dst_type = dst.is_virtual ? "virtual" : "physical";
    const char *dst_loc = dst.aperture == UVM_APERTURE_SYS ? "sysmem" : "vidmem";

    NvU64 value64 = (test_iteration + 2) * (1ull << 32) + (test_iteration + 1);
    NvU64 test_value = 0, expected_value = 0;

    status = uvm_push_begin(gpu->channel_manager, UVM_CHANNEL_TYPE_GPU_INTERNAL, &push,
            "Memset %s %s (0x%llx) and memcopy to %s %s (0x%llx), iter %d",
            src_type, src_loc, src.address, dst_type, dst_loc, dst.address, test_iteration);
    TEST_CHECK_RET(status == NV_OK);

    // Memset src with the appropriate element size, then memcpy to dst and from
    // dst to the verif location (physical sysmem).

    push_memset(&push, src, value64, element_size, size);
    gpu->parent->ce_hal->memcopy(&push, dst, src, size);
    gpu->parent->ce_hal->memcopy(&push, gpu_verif_addr, dst, size);

    status = uvm_push_end_and_wait(&push);
    TEST_CHECK_RET(status == NV_OK);

    for (i = 0; i < size / element_size; i++) {
        switch (element_size) {
            case 1:
                expected_value = (NvU8)value64;
                test_value = ((NvU8 *)cpu_verif_addr)[i];
                break;
            case 4:
                expected_value = (NvU32)value64;
                test_value = ((NvU32 *)cpu_verif_addr)[i];
                break;
            case 8:
                expected_value = value64;
                test_value = ((NvU64 *)cpu_verif_addr)[i];
                break;
            default:
                UVM_ASSERT(0);
        }

        if (test_value != expected_value) {
            UVM_TEST_PRINT("memset_%zu of %s %s and memcpy into %s %s failed, value[%zu] = 0x%llx instead of 0x%llx\n",
                           element_size, src_type, src_loc, dst_type, dst_loc,
                           i, test_value, expected_value);
            return NV_ERR_INVALID_STATE;
        }
    }

    return NV_OK;
}

#define MEM_TEST_SIZE UVM_CHUNK_SIZE_64K
#define MEM_TEST_ITERS 4

static NV_STATUS test_memcpy_and_memset(uvm_gpu_t *gpu)
{
    NV_STATUS status;
    uvm_mem_t *verif_mem = NULL;
    uvm_mem_t *sys_phys_mem = NULL;
    uvm_gpu_chunk_t *gpu_phys_chunk = NULL;
    uvm_rm_mem_t *gpu_virt = NULL;
    uvm_rm_mem_t *host_virt = NULL;
    uvm_gpu_address_t test_mem[4];
    uvm_gpu_address_t gpu_verif_addr;
    static const size_t element_sizes[] = {1, 4, 8};
    void *cpu_verif_addr;
    size_t i, j, k, s;
    uvm_mem_alloc_params_t mem_params = {0};

    status = uvm_mem_alloc_sysmem_and_map_cpu_kernel(MEM_TEST_SIZE, &verif_mem);
    if (status != NV_OK)
        goto done;
    status = uvm_mem_map_gpu_kernel(verif_mem, gpu);
    if (status != NV_OK)
        goto done;

    gpu_verif_addr = uvm_mem_gpu_address_virtual_kernel(verif_mem, gpu);
    cpu_verif_addr = uvm_mem_get_cpu_addr_kernel(verif_mem);

    mem_params.page_size = MEM_TEST_SIZE;
    mem_params.size = MEM_TEST_SIZE;
    status = uvm_mem_alloc(&mem_params, &sys_phys_mem);
    if (status != NV_OK)
        goto done;
    status = uvm_mem_map_cpu(sys_phys_mem, NULL);
    if (status != NV_OK)
        goto done;
    status = uvm_mem_map_gpu_phys(sys_phys_mem, gpu);
    if (status != NV_OK)
        goto done;
    memset(uvm_mem_get_cpu_addr_kernel(sys_phys_mem), 0, MEM_TEST_SIZE);
    test_mem[0] = uvm_mem_gpu_address_physical(sys_phys_mem, gpu, 0, MEM_TEST_SIZE);

    status = uvm_pmm_gpu_alloc_kernel(&gpu->pmm, 1, MEM_TEST_SIZE, UVM_PMM_ALLOC_FLAGS_NONE, &gpu_phys_chunk, NULL);
    if (status != NV_OK)
        goto done;
    test_mem[1] = uvm_gpu_address_physical(UVM_APERTURE_VID, gpu_phys_chunk->address);

    status = uvm_rm_mem_alloc(gpu, UVM_RM_MEM_TYPE_GPU, MEM_TEST_SIZE, &gpu_virt);
    if (status != NV_OK)
        goto done;
    test_mem[2] = uvm_gpu_address_virtual(uvm_rm_mem_get_gpu_va(gpu_virt, gpu));

    status = uvm_rm_mem_alloc(gpu, UVM_RM_MEM_TYPE_SYS, MEM_TEST_SIZE, &host_virt);
    if (status != NV_OK)
        goto done;
    test_mem[3] = uvm_gpu_address_virtual(uvm_rm_mem_get_gpu_va(host_virt, gpu));

    for (i = 0; i < MEM_TEST_ITERS; ++i) {
        for (s = 0; s < ARRAY_SIZE(element_sizes); s++) {
            status = test_unaligned_memset(gpu,
                                           gpu_verif_addr,
                                           cpu_verif_addr,
                                           MEM_TEST_SIZE,
                                           element_sizes[s],
                                           i);
            if (status != NV_OK)
                goto done;
        }
    }

    for (i = 0; i < MEM_TEST_ITERS; ++i) {
        for (j = 0; j < ARRAY_SIZE(test_mem); ++j) {
            for (k = 0; k < ARRAY_SIZE(test_mem); ++k) {
                for (s = 0; s < ARRAY_SIZE(element_sizes); s++) {
                    status = test_memcpy_and_memset_inner(gpu,
                                                          test_mem[k],
                                                          test_mem[j],
                                                          MEM_TEST_SIZE,
                                                          element_sizes[s],
                                                          gpu_verif_addr,
                                                          cpu_verif_addr,
                                                          i);
                    if (status != NV_OK)
                        goto done;
                }
            }
        }
    }

done:
    if (host_virt)
        uvm_rm_mem_free(host_virt);
    if (gpu_virt)
        uvm_rm_mem_free(gpu_virt);
    if (gpu_phys_chunk)
        uvm_pmm_gpu_free(&gpu->pmm, gpu_phys_chunk, NULL);

    uvm_mem_free(sys_phys_mem);
    uvm_mem_free(verif_mem);

    return status;
}

static NV_STATUS test_semaphore_alloc_sem(uvm_gpu_t *gpu,
                                          const size_t size,
                                          uvm_mem_t **mem_out)
{
    NV_STATUS status;
    NvU64 gpu_va;
    uvm_mem_t *mem;
    uvm_mem_alloc_params_t params = { 0 };

    params.size = size;
    params.page_size = UVM_PAGE_SIZE_DEFAULT;

    status = uvm_mem_alloc(&params, &mem);
    TEST_CHECK_RET(status == NV_OK);

    status = uvm_mem_map_cpu(mem, NULL);
    TEST_CHECK_GOTO(status == NV_OK, error);

    status = uvm_mem_map_gpu_kernel(mem, gpu);
    TEST_CHECK_GOTO(status == NV_OK, error);

    gpu_va = uvm_mem_get_gpu_va_kernel(mem, gpu);

    // This semaphore resides in the uvm_mem region, i.e., it has the GPU VA
    // MSbit set. The intent is to validate semaphore operations when the
    // semaphore's VA is in the high-end of the GPU effective virtual address
    // space spectrum, i.e., its VA upper-bit is set.
    TEST_CHECK_GOTO(gpu_va & (1ULL << (gpu->address_space_tree.hal->num_va_bits() - 1)), error);

    *mem_out = mem;

    return NV_OK;

error:
    uvm_mem_free(mem);
    return status;
}

// test_semaphore_reduction_inc is similar in concept to test_membar(). It uses
// uvm_mem (instead of uvm_rm_mem) as the semaphore, i.e., it assumes that the
// CE HAL has been validated, since uvm_mem needs the CE memset/memcopy to be
// operational as a pre-requisite for GPU PTE writes. The purpose of
// test_semaphore_reduction_inc is to validate the reduction inc operation on
// semaphores with their VA's upper-bit set.
static NV_STATUS test_semaphore_reduction_inc(uvm_gpu_t *gpu)
{
    NV_STATUS status;
    uvm_push_t push;
    uvm_mem_t *mem;
    NvU64 gpu_va;
    NvU32 i;
    NvU32 *host_ptr = NULL;
    NvU32 value;

    // Semaphore reduction needs 1 word (4 bytes).
    const size_t size = sizeof(NvU32);

    if (!uvm_gpu_is_gk110_plus(gpu)) {
        // semaphore_reduction_inc is only supported on GK110+
        return NV_OK;
    }

    status = test_semaphore_alloc_sem(gpu, size, &mem);
    TEST_CHECK_RET(status == NV_OK);

    // Initialize the counter of reductions.
    host_ptr = uvm_mem_get_cpu_addr_kernel(mem); 
    TEST_CHECK_GOTO(host_ptr != NULL, done);
    *host_ptr = 0;

    gpu_va = uvm_mem_get_gpu_va_kernel(mem, gpu);

    status = uvm_push_begin(gpu->channel_manager, UVM_CHANNEL_TYPE_GPU_INTERNAL, &push, "semaphore_reduction_inc test");
    TEST_CHECK_GOTO(status == NV_OK, done);

    for (i = 0; i < REDUCTIONS; i++) {
        uvm_push_set_flag(&push, UVM_PUSH_FLAG_CE_NEXT_MEMBAR_NONE);
        gpu->parent->ce_hal->semaphore_reduction_inc(&push, gpu_va, i+1);
    }

    status = uvm_push_end_and_wait(&push);
    TEST_CHECK_GOTO(status == NV_OK, done);

    value = *host_ptr;
    if (value != REDUCTIONS) {
        UVM_TEST_PRINT("Value = %u instead of %u, GPU %s\n", value, REDUCTIONS, uvm_gpu_name(gpu));
        status = NV_ERR_INVALID_STATE;
        goto done;
    }

done:
    uvm_mem_free(mem);

    return status;
}

static NV_STATUS test_semaphore_release(uvm_gpu_t *gpu)
{
    NV_STATUS status;
    uvm_push_t push;
    uvm_mem_t *mem;
    NvU64 gpu_va;
    NvU32 value;
    NvU32 *host_ptr = NULL;
    NvU32 payload = 0xA5A55A5A;

    // Semaphore release needs 1 word (4 bytes).
    const size_t size = sizeof(NvU32);

    status = test_semaphore_alloc_sem(gpu, size, &mem);
    TEST_CHECK_RET(status == NV_OK);

    // Initialize the payload.
    host_ptr = uvm_mem_get_cpu_addr_kernel(mem); 
    TEST_CHECK_GOTO(host_ptr != NULL, done);
    *host_ptr = 0;

    gpu_va = uvm_mem_get_gpu_va_kernel(mem, gpu);

    status = uvm_push_begin(gpu->channel_manager, UVM_CHANNEL_TYPE_GPU_INTERNAL, &push, "semaphore_release test");
    TEST_CHECK_GOTO(status == NV_OK, done);

    gpu->parent->ce_hal->semaphore_release(&push, gpu_va, payload);

    status = uvm_push_end_and_wait(&push);
    TEST_CHECK_GOTO(status == NV_OK, done);

    value = *host_ptr;
    if (value != payload) {
        UVM_TEST_PRINT("Semaphore payload = %u instead of %u, GPU %s\n", value, payload, uvm_gpu_name(gpu));
        status = NV_ERR_INVALID_STATE;
        goto done;
    }

done:
    uvm_mem_free(mem);

    return status;
}

static NV_STATUS test_semaphore_timestamp(uvm_gpu_t *gpu)
{
    NV_STATUS status;
    uvm_push_t push;
    uvm_mem_t *mem;
    NvU64 gpu_va;
    NvU32 i;
    NvU64 *timestamp;
    NvU64 last_timestamp = 0;

    // 2 iterations:
    //   1: compare retrieved timestamp with 0;
    //   2: compare retrieved timestamp with previous timestamp (obtained in 1).
    const NvU32 iterations = 2;

    // Semaphore timestamp is 4 words long (16 bytes).
    const size_t size = 16;

    status = test_semaphore_alloc_sem(gpu, size, &mem);
    TEST_CHECK_RET(status == NV_OK);

    timestamp = uvm_mem_get_cpu_addr_kernel(mem); 
    TEST_CHECK_GOTO(timestamp != NULL, done);
    memset(timestamp, 0, size);

    // Shift the timestamp pointer to where the semaphore timestamp info is.
    timestamp += 1;

    gpu_va = uvm_mem_get_gpu_va_kernel(mem, gpu);

    for (i = 0; i < iterations; i++) {
        status = uvm_push_begin(gpu->channel_manager,
                                UVM_CHANNEL_TYPE_GPU_INTERNAL,
                                &push,
                                "semaphore_timestamp test, iter: %u",
                                i);
        TEST_CHECK_GOTO(status == NV_OK, done);

        gpu->parent->ce_hal->semaphore_timestamp(&push, gpu_va);

        status = uvm_push_end_and_wait(&push);
        TEST_CHECK_GOTO(status == NV_OK, done);

        TEST_CHECK_GOTO(*timestamp != 0, done);
        TEST_CHECK_GOTO(*timestamp >= last_timestamp, done);
        last_timestamp = *timestamp;
    }

done:
    uvm_mem_free(mem);

    return status;
}

static NV_STATUS test_ce(uvm_va_space_t *va_space, bool skipTimestampTest)
{
    uvm_gpu_t *gpu;

    for_each_va_space_gpu(gpu, va_space) {
        TEST_CHECK_RET(test_non_pipelined(gpu) == NV_OK);
        TEST_CHECK_RET(test_membar(gpu) == NV_OK);
        TEST_CHECK_RET(test_memcpy_and_memset(gpu) == NV_OK);
        TEST_CHECK_RET(test_semaphore_reduction_inc(gpu) == NV_OK);
        TEST_CHECK_RET(test_semaphore_release(gpu) == NV_OK);
        if (!skipTimestampTest)
            TEST_CHECK_RET(test_semaphore_timestamp(gpu) == NV_OK);
    }

    return NV_OK;
}

NV_STATUS uvm_test_ce_sanity(UVM_TEST_CE_SANITY_PARAMS *params, struct file *filp)
{
    NV_STATUS status;
    uvm_va_space_t *va_space = uvm_va_space_get(filp);

    uvm_va_space_down_read_rm(va_space);

    status = test_ce(va_space, params->skipTimestampTest);
    if (status != NV_OK)
        goto done;

done:
    uvm_va_space_up_read_rm(va_space);

    return status;
}
