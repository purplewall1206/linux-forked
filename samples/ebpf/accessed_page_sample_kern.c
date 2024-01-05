
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

struct event
{
	char id[128];
	unsigned long start;
	unsigned long end;
	unsigned long addr;
	unsigned long pteprot;
	unsigned long vm_flags;
	int ishuge;
	int accessed;
	int index;
	int pte_level; // pud2 pmd1 pte0
};


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, sizeof(struct event) * 102400);
} rb SEC(".maps");



int get_page_index_vma(unsigned long addr, struct vm_area_struct *vma, bool ispmd)
{
	unsigned long start = BPF_CORE_READ(vma, vm_start);
	unsigned long end = BPF_CORE_READ(vma, vm_end);
	// unsigned long step = (end - start) / (ispmd ? PAGE_SIZE*4096 : PAGE_SIZE);
	if (ispmd < 2)
		return (addr - start) / (ispmd ? PAGE_SIZE*4096 : PAGE_SIZE);
	else
		return (addr - start) / (PAGE_SIZE * 4096 * 4096);
}

extern int bpf_get_vma_id(struct vm_area_struct *vma, char *buf)__ksym;

// __weak noinline void active_scan_pte_probe(pte_t *pte, unsigned long addr, struct vm_area_struct *vma, bool accessed)
SEC("fentry/active_scan_pte_probe")
int BPF_PROG(fentry_mglru_pte_probe, unsigned long pte, unsigned long addr, struct vm_area_struct *vma, bool accessed)
{
	struct event *e;

	e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
	if (!e)
		return 0;
	bpf_get_vma_id(vma, e->id);
	e->addr = addr;
	e->start = BPF_CORE_READ(vma, vm_start);
	e->end = BPF_CORE_READ(vma, vm_end);
	e->pteprot = pte & (unsigned long) 0xffff000000000fff;
	e->vm_flags = vma->vm_flags;
	e->ishuge = 0;
	e->accessed = accessed;
	e->index =  get_page_index_vma(addr, vma, false);
	e->pte_level = 0;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

#define _PAGE_BIT_PSE		7
#define _PAGE_PSE			((unsigned long) 1 << _PAGE_BIT_PSE)

SEC("fentry/active_scan_pmd_probe")
int BPF_PROG(fentry_mglru_pmd_probe,unsigned long pmd, unsigned long addr, struct vm_area_struct *vma, bool accessed)
{
	struct event *e;

	e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
	if (!e)
		return 0;
	bpf_get_vma_id(vma, e->id);
	e->addr = addr;
	e->start = BPF_CORE_READ(vma, vm_start);
	e->end = BPF_CORE_READ(vma, vm_end);
	e->pteprot = pmd & (unsigned long) 0xffff000000000fff;
	e->vm_flags = vma->vm_flags;
	e->ishuge = (pmd & _PAGE_PSE > 0) ? 1 : 0;
	e->accessed = accessed;
	e->index =  get_page_index_vma(addr, vma, true);
	e->pte_level = 1;

	bpf_ringbuf_submit(e, 0);
	return 0;
}


SEC("fentry/active_scan_pud_probe")
int BPF_PROG(fentry_mglru_pud_probe,unsigned long pud, unsigned long addr, struct vm_area_struct *vma, bool accessed)
{
	struct event *e;

	e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
	if (!e)
		return 0;
	bpf_get_vma_id(vma, e->id);
	e->addr = addr;
	e->start = BPF_CORE_READ(vma, vm_start);
	e->end = BPF_CORE_READ(vma, vm_end);
	e->pteprot = pud & (unsigned long) 0xffff000000000fff;
	e->vm_flags = vma->vm_flags;
	e->ishuge = (pud & _PAGE_PSE > 0) ? 1 : 0;;
	e->accessed = accessed;
	e->index =  get_page_index_vma(addr, vma, true);
	e->pte_level = 2;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

extern int bpf_run_aging(int memcg_id, bool can_swap, bool force_scan) __ksym;

extern int bpf_active_page_scan(int memcg_id, pid_t pid) __ksym;

struct args {
	int memcg_id;
	int pid;
};

int c = 0;

SEC("syscall")
int memcg_run_aging(struct args *ctx)
{
	int err;

	// err = bpf_run_aging(ctx->memcg_id, true, true);
	err = bpf_active_page_scan(ctx->memcg_id, ctx->pid);

	if (err != 0) {
		return 0;
	}
	bpf_printk("scaned %d times", ++c);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

