#!/bin/bash

git send-email 0001-HotBPF-Prevent-Kernel-Heap-based-Exploitation.patch \
    --to linux-kernel@vger.kernel.org \
    --cc jmorris@namei.org \
    --cc ast@kernel.org \
    --cc kpsingh@kernel.org \
    --cc keescook@chromium.org \
    --cc bpf@vger.kernel.org \
    --cc yueqi.chen@colorado.edu \
    --cc linux-hardening@vger.kernel.org