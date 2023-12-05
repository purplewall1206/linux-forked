
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>

int count = 0;
int target_pid = 0;
// SEC("kprobe/__kmalloc")
// int bpf_prog1(struct pt_regs *ctx)
// {
//     ++count;
//     // if (count % 10 == 0)
//         bpf_printk("--%d--\n", count);
//     return 0;
// }

// ffffffff813916f0 <single_open>:
// ...
// ffffffff8139171a:       e8 31 f6 f1 ff          call   ffffffff812b0d50 <kmalloc_trace> ffffffff8139171b: R_X86_64_PLT32        kmalloc_trace-0x4
// ffffffff8139171f:       48 85 c0                test   %rax,%rax

// python3 -c 'print(hex(0xffffffff8139171a-0xffffffff813916f0))'
// SEC("kprobe/single_open+0x5")
// int BPF_KPROBE(prog2)
// {
//     bpf_printk("===%lx===\n", ctx->ip);
//     return 0;
// }

SEC("fentry/mglru_pte_probe")
int BPF_PROG(fentry_mglru_pte_probe, pid_t pid, unsigned int nid,
	     unsigned long addr, unsigned long len, bool anon)
{
	int err = 0;
    char name[32];

	// if (pid != target_pid)
	// 	return 0;
	// err = probe(nid, addr, len, anon);
    bpf_get_current_comm(name, 32);
    bpf_printk("PTE called addr:0x%lx len:%lu, comm:%s\n", addr, len, name);
	if (err)
		bpf_printk("PTE called addr:0x%lx len:%lu error:%ld", addr, len,
			   err);
	return 0;
}

SEC("fentry/mglru_pmd_probe")
int BPF_PROG(fentry_mglru_pmd_probe, pid_t pid, unsigned int nid,
	     unsigned long addr, unsigned long len, bool anon)
{
	int err = 0;

	if (pid != target_pid)
		return 0;
	// err = probe(nid, addr, len, anon);
	if (err)
		bpf_printk("PMD called addr:0x%lx len:%lu error:%ld", addr, len,
			   err);
	return 0;
}

extern int bpf_run_aging(int memcg_id, bool can_swap, bool force_scan) __ksym;

struct args {
	int memcg_id;
};

SEC("syscall")
int memcg_run_aging(struct args *ctx)
{
	int err;

	err = bpf_run_aging(ctx->memcg_id, true, true);

	if (err != 0) {
		bpf_printk("aging failed for memcg %ld with error %d",
			   ctx->memcg_id, err);
		return 0;
	}
	bpf_printk("aging succeeded for memcg %ld", ctx->memcg_id);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

