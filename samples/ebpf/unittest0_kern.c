
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
// #include <linux/mm_types.h>

int count = 0;
int target_pid = 0;

struct vm_area_struct {
        unsigned long          vm_start;             /*     0     8 */
        unsigned long          vm_end;               /*     8     8 */
        u64 *         vm_mm;                /*    16     8 */
        u64                   vm_page_prot;         /*    24     8 */
        unsigned long          vm_flags;             /*    32     8 */
        struct {
                u64     rb[3];                   /*    40    24 */
                /* --- cacheline 1 boundary (64 bytes) --- */
                unsigned long  rb_subtree_last;      /*    64     8 */
        } shared;                                        /*    40    32 */
        u64           anon_vma_chain[2];       /*    72    16 */
        u64 *          anon_vma;             /*    88     8 */
        u64  * vm_ops;     /*    96     8 */
        unsigned long          vm_pgoff;             /*   104     8 */
        struct file *              vm_file;              /*   112     8 */
        struct file *              vm_prfile;            /*   120     8 */
        /* --- cacheline 2 boundary (128 bytes) --- */
        void *                     vm_private_data;      /*   128     8 */
        u64 *     anon_name;            /*   136     8 */
        u64              swap_readahead_info;  /*   144     8 */
        u64 *         vm_policy;            /*   152     8 */
        u64  vm_userfaultfd_ctx;   /*   160     8 */

        /* size: 168, cachelines: 3, members: 17 */
        /* last cacheline: 40 bytes */
};

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
// #define PAGE_SIZE 4096

int get_page_index_vma(unsigned long addr, struct vm_area_struct *vma, bool ispmd)
{
	unsigned long start = BPF_CORE_READ(vma, vm_start);
	unsigned long end = BPF_CORE_READ(vma, vm_end);
	unsigned long step = (end - start) / (ispmd ? PAGE_SIZE*4096 : PAGE_SIZE);
	return (addr - start) / step;
}

extern char *bpf_get_file_name(struct file *file) __ksym;

// __weak noinline void active_scan_pte_probe(pte_t *pte, unsigned long addr, struct vm_area_struct *vma)
SEC("fentry/active_scan_pte_probe")
int BPF_PROG(fentry_mglru_pte_probe, pte_t *pte, unsigned long addr, struct vm_area_struct *vma)
{
	int err = 0;
	unsigned long start = BPF_CORE_READ(vma, vm_start);
	unsigned long end = BPF_CORE_READ(vma, vm_end);
	struct file *f = BPF_CORE_READ(vma, vm_file);
    // char name[32];

	// if (pid != target_pid)
	// 	return 0;
	// err = probe(nid, addr, len, anon);
	bool anon = BPF_CORE_READ(vma, vm_file) == NULL ? true : false;
	int index = get_page_index_vma(addr, vma, false);
	char *name = bpf_get_file_name(f);

	if (name)
		bpf_printk("PTE: addr:%016lx, index: %d, %s", addr, index, name);
	else 
		bpf_printk("PTE: addr:%016lx, index: %d, %016lx", addr, index, BPF_CORE_READ(vma, vm_flags));

	if (err)
		bpf_printk("PTE called addr:0x%lx index:%d error:%ld", addr, index, err);
	return 0;
}

// SEC("fentry/mglru_pmd_probe")
// int BPF_PROG(fentry_mglru_pmd_probe,pmd_t *pmd, unsigned long addr, struct vm_area_struct *vma)
// {
// 	int err = 0;
// 	if (vmaname == NULL) {
// 		bpf_printk("PMD: %016lx, %d, %s\n", addr, vma_index, "anon");
// 	} else {
// 		bpf_printk("PMD: %016lx, %d, %s\n", addr, vma_index, vmaname);
// 	}
    
// 	if (err)
// 		bpf_printk("PMD called addr:0x%lx index:%d error:%ld", addr, vma_index, err);
// 	return 0;
// }

extern int bpf_run_aging(int memcg_id, bool can_swap, bool force_scan) __ksym;

extern int bpf_active_page_scan(int memcg_id, pid_t pid) __ksym;

struct args {
	int memcg_id;
	int pid;
};

SEC("syscall")
int memcg_run_aging(struct args *ctx)
{
	int err;

	// err = bpf_run_aging(ctx->memcg_id, true, true);
	err = bpf_active_page_scan(ctx->memcg_id, ctx->pid);

	if (err != 0) {
		// bpf_printk("aging failed for memcg %ld with error %d",
		// 	   ctx->memcg_id, err);
		return 0;
	}
	bpf_printk("aging succeeded for memcg %ld", ctx->memcg_id);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

