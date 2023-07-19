// SPDX-License-Identifier: GPL-2.0
/*
 * HotBPF example kernel side
 * Copyright Zicheng Wang, Yueqi Chen
 */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>

#define ___GFP_DMA		0x01u
#define ___GFP_RECLAIMABLE	0x10u
#define ___GFP_ACCOUNT		0x400000u


struct kmem_cache {
	unsigned long cpu_slab;
	unsigned int flags;
	unsigned long min_partial;
	unsigned int size;
	unsigned int object_size;
	unsigned long reciprocal_size;
	unsigned int offset;
	unsigned int cpu_partial;
	unsigned int oo;
	unsigned int max;
	unsigned int min;
	unsigned int allocflags;
	int refcount;
    /* size: 8408, cachelines: 132, members: 26 */
    /* sum members: 8392, holes: 4, sum holes: 16 */
    /* paddings: 1, sum paddings: 2 */
    /* last cacheline: 24 bytes */
};


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 40960);
	__type(key, u64);	// ip^size^priv^zone
	__type(value, u64);	// cache addr
} key2cache SEC(".maps");

u64 get_key(u64 ip, u32 size, u32 uid, u32 zone)
{
	return ip ^ (u64) size ^ (u64) uid ^ (u64) zone;
}

u32 get_size(u32 size)
{
	u32 ret = (size + 4096) / 4096;

	return (ret + 1) * 4096;
}

u32 get_zone(u32 gfp_flags)
{
	u32 ret = 0;

	if (gfp_flags & ___GFP_DMA)
		ret = 1;
	else if (gfp_flags & ___GFP_RECLAIMABLE)
		ret = 2;
	else if (gfp_flags & ___GFP_ACCOUNT)
		ret = 3;

	return ret;
}

// ffffffff813371a0 <single_open>:
// ...
// ffffffff813371c5:   call   ffffffff812d61b0 <kmem_cache_alloc_trace>
// ffffffff813371ca:   test   %rax,%rax

// void *kmem_cache_alloc_trace(struct kmem_cache *s, gfp_t gfpflags, size_t size)
// python3 -c 'print(hex(0xffffffff813371c5-0xffffffff813371a0))'
SEC("kprobe/single_open+0x25")
int BPF_KPROBE(HANDLE_kmem_cache_alloc_trace)
{
	u64 ip = ctx->ip;
	u64 *pv;
	struct kmem_cache *cache = (struct kmem_cache *) ctx->di;
	u64 alloc_size = BPF_CORE_READ(cache, size);
	u32 gfp_flags = (u32) ctx->si;
	u32 uid = bpf_get_current_uid_gid() >> 32;
	u32 zone = get_zone(gfp_flags);
	u64 key = get_key(ip, alloc_size, uid, zone);
	u64 cache_addr = 0;
	u64 alloc_addr = 0;
	int err = 0;

    // if there is a slab cache
	u64 *pcache = bpf_map_lookup_elem(&key2cache, &key);

	if (!pcache) {
		cache_addr = bpf_create_slub_cache(alloc_size, gfp_flags, key);
		if (!cache_addr) {
			bpf_printk("probe create cache failed\n");
			return -1;
		}
		err = bpf_map_update_elem(&key2cache, &key, &cache_addr, BPF_ANY);
		if (err < 0) {
			bpf_printk("update key2cache failed: %d\n", err);
			return err;
		}
	}

	// alloc a new object
	cache_addr = *pcache;
	alloc_addr = bpf_cache_alloc(cache_addr, gfp_flags);
	if (alloc_addr == 0) {
		bpf_printk("probe kmalloc failed\n");
		return -1;
	}
	bpf_printk("===HotBPF isolate single_open %lx===\n", alloc_addr);

	bpf_jmp_next(ctx, ip + 0x4, alloc_addr);

	return 0;
}


// ffffffff81534d70 <bio_kmalloc>:
// ...
// ffffffff81534d9a:   call   ffffffff812d70e0 <__kmalloc>
// ffffffff81534d9f:   test   %rax,%rax

// void *__kmalloc(size_t size, gfp_t flags)
// python3 -c 'print(hex(0xffffffff81534d9a-0xffffffff81534d70))'
SEC("kprobe/bio_kmalloc+0x2a")
int BPF_KPROBE(HANDLE___kmalloc)
{
	u64 ip = ctx->ip;
	u64 *pv;
	u64 alloc_size = get_size(ctx->di);
	u32 gfp_flags = (u32) ctx->si;
	u32 uid = bpf_get_current_uid_gid() >> 32;
	u32 zone = get_zone(gfp_flags);
	u64 key = get_key(ip, alloc_size, uid, zone);
	u64 cache_addr = 0;
	u64 alloc_addr = 0;
	int err = 0;

	// if there is a slab cache
	u64 *pcache = bpf_map_lookup_elem(&key2cache, &key);

	if (!pcache) {
		cache_addr = bpf_create_slub_cache(alloc_size, gfp_flags, key);
		if (!cache_addr) {
			bpf_printk("probe create cache failed\n");
			return -1;
		}
		err = bpf_map_update_elem(&key2cache, &key, &cache_addr, BPF_ANY);
		if (err < 0) {
			bpf_printk("update key2cache failed: %d\n", err);
			return err;
		}
	} else {
		cache_addr = *pcache;
	}

	// alloc a new object
	alloc_addr = bpf_cache_alloc(cache_addr, gfp_flags);
	if (alloc_addr == 0) {
		bpf_printk("probe kmalloc failed\n");
		return -1;
	}
	bpf_printk("===HotBPF isolate bio_kmalloc %lx===\n", alloc_addr);

	bpf_jmp_next(ctx, ip + 0x4, alloc_addr);

	return 0;
}



char LICENSE[] SEC("license") = "Dual BSD/GPL";
