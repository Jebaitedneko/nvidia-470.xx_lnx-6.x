/*******************************************************************************
    Copyright (c) 2016, 2016 NVIDIA Corporation

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

#include "uvm_hmm.h"

// You have to opt in, in order to use HMM. Once "HMM bringup" is complete,
// the module parameter value should be reversed so that HMM is enabled by default.
//
// You need all of the following, in order to actually run HMM:
//
//     1) A Linux kernel with CONFIG_HMM set and nvidia-uvm.ko compiled with NV_BUILD_SUPPORTS_HMM=1.
//
//     2) UVM Kernel module parameter set: uvm_hmm=1
//
//     3) ATS must not be enabled
//
//     4) UvmInitialize() called without the UVM_INIT_FLAGS_DISABLE_HMM or
//        UVM_INIT_FLAGS_MULTI_PROCESS_SHARING_MODE flags
//
static int uvm_hmm = 0;
module_param(uvm_hmm, int, S_IRUGO);
MODULE_PARM_DESC(uvm_hmm, "Enable (1) or disable (0) HMM mode. Default: 0. "
                          "Ignored if CONFIG_HMM is not set, or if ATS settings conflict with HMM.");
























































