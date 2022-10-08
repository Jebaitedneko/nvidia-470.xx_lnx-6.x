/*******************************************************************************
    Copyright (c) 2020 NVIDIA Corporation

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

#include "uvm_global.h"
#include "uvm_common.h"
#include "uvm_hal.h"
#include "uvm_push.h"
#include "uvm_test.h"
#include "uvm_va_space.h"
#include "uvm_mem.h"

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

// This test is similiar to the test_semaphore_release() test in uvm_ce_test.c,
// except that this one uses host_hal->semaphore_release();
static NV_STATUS test_semaphore_release(uvm_gpu_t *gpu)
{
    NV_STATUS status;
    uvm_push_t push;
    uvm_mem_t *mem;
    NvU64 gpu_va;
    NvU32 value;
    NvU32 *cpu_ptr = NULL;
    NvU32 payload = 0xA5A55A5A;

    // Semaphore release needs 1 word (4 bytes).
    const size_t size = sizeof(NvU32);

    status = test_semaphore_alloc_sem(gpu, size, &mem);
    TEST_CHECK_RET(status == NV_OK);

    gpu_va = uvm_mem_get_gpu_va_kernel(mem, gpu);

    // Skip the test when Host cannot address the semaphore.
    if (gpu_va >= gpu->parent->max_host_va) {
        goto done;
    }

    // Initialize the payload.
    cpu_ptr = uvm_mem_get_cpu_addr_kernel(mem); 
    TEST_CHECK_GOTO(cpu_ptr != NULL, done);
    *cpu_ptr = 0;

    status = uvm_push_begin(gpu->channel_manager, UVM_CHANNEL_TYPE_GPU_INTERNAL, &push, "semaphore_release test");
    TEST_CHECK_GOTO(status == NV_OK, done);

    gpu->parent->host_hal->semaphore_release(&push, gpu_va, payload);

    status = uvm_push_end_and_wait(&push);
    TEST_CHECK_GOTO(status == NV_OK, done);

    value = *cpu_ptr;
    if (value != payload) {
        UVM_TEST_PRINT("Semaphore payload = %u instead of %u, GPU %s\n", value, payload, uvm_gpu_name(gpu));
        status = NV_ERR_INVALID_STATE;
        goto done;
    }

done:
    uvm_mem_free(mem);

    return status;
}

static NV_STATUS test_semaphore_acquire(uvm_gpu_t *gpu)
{
    NV_STATUS status;
    uvm_push_t push;
    uvm_mem_t *mem;
    uvm_spin_loop_t spin;
    NvU64 gpu_va;
    NvU32 *cpu_ptr = NULL;
    NvU32 *cpu_sema_A, *cpu_sema_B, *cpu_sema_C;
    NvU64 gpu_sema_va_A, gpu_sema_va_B, gpu_sema_va_C;
    bool check_sema_C;

    // The semaphore is one word long(4 bytes), we use three semaphores.
    const size_t sema_size = 4;
    const size_t size = sema_size * 3;

    status = test_semaphore_alloc_sem(gpu, size, &mem);
    TEST_CHECK_RET(status == NV_OK);

    gpu_va = uvm_mem_get_gpu_va_kernel(mem, gpu);
    gpu_sema_va_A = gpu_va;
    gpu_sema_va_B = gpu_va + sema_size;
    gpu_sema_va_C = gpu_va + 2 * sema_size;

    // Skip the test when Host cannot address the semaphore.
    if (gpu_va >= gpu->parent->max_host_va) {
        goto done;
    }

    cpu_ptr = uvm_mem_get_cpu_addr_kernel(mem);
    TEST_CHECK_GOTO(cpu_ptr != NULL, done);
    memset(cpu_ptr, 0, size);
    cpu_sema_A = cpu_ptr;
    cpu_sema_B = cpu_ptr + 1;
    cpu_sema_C = cpu_ptr + 2;

    status = uvm_push_begin(gpu->channel_manager, UVM_CHANNEL_TYPE_GPU_INTERNAL, &push, "semaphore_acquire test");
    TEST_CHECK_GOTO(status == NV_OK, done);

    gpu->parent->host_hal->semaphore_release(&push, gpu_sema_va_A, 1);
    gpu->parent->host_hal->semaphore_acquire(&push, gpu_sema_va_B, 1);
    gpu->parent->host_hal->semaphore_release(&push, gpu_sema_va_C, 1);

    uvm_push_end(&push);

    // Wait for sema_A release.
    UVM_SPIN_WHILE(UVM_READ_ONCE(*cpu_sema_A) != 1, &spin);

    // Sleep for 10ms, the GPU waits while sema_B is held by us.
    msleep(10);

    check_sema_C = UVM_READ_ONCE(*cpu_sema_C) == 0;

    // memory fence/barrier, check comment in
    // uvm_gpu_semaphore.c:uvm_gpu_semaphore_set_payload() for details.
    mb();

    // Release sema_B.
    UVM_WRITE_ONCE(*cpu_sema_B, 1);

    // Wait for the GPU to release sema_C, i.e., the end of the push.
    status = uvm_push_wait(&push);
    TEST_CHECK_GOTO(status == NV_OK, done);

    // check_sema_C is validated here to ensure the push has ended and not
    // interrupted in the middle had the check failed.
    TEST_CHECK_GOTO(check_sema_C, done);
    TEST_CHECK_GOTO(UVM_READ_ONCE(*cpu_sema_C) == 1, done);

done:
    uvm_mem_free(mem);

    return status;
}

static NV_STATUS test_host(uvm_va_space_t *va_space)
{
    uvm_gpu_t *gpu;

    for_each_va_space_gpu(gpu, va_space) {
        TEST_CHECK_RET(test_semaphore_release(gpu) == NV_OK);
        TEST_CHECK_RET(test_semaphore_acquire(gpu) == NV_OK);
    }

    return NV_OK;
}

NV_STATUS uvm_test_host_sanity(UVM_TEST_HOST_SANITY_PARAMS *params, struct file *filp)
{
    NV_STATUS status;
    uvm_va_space_t *va_space = uvm_va_space_get(filp);

    uvm_va_space_down_read(va_space);

    status = test_host(va_space);
    if (status != NV_OK)
        goto done;

done:
    uvm_va_space_up_read(va_space);

    return status;
}
