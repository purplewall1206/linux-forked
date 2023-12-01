
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
        unsigned long    cpu_slab;             /*     0     8 */
        unsigned int               flags;                /*     8     4 */

        /* XXX 4 bytes hole, try to pack */

        long unsigned int          min_partial;          /*    16     8 */
        unsigned int               size;                 /*    24     4 */
        unsigned int               object_size;          /*    28     4 */
        unsigned long   reciprocal_size;      /*    32     8 */

        /* XXX last struct has 2 bytes of padding */

        unsigned int               offset;               /*    40     4 */
        unsigned int               cpu_partial;          /*    44     4 */
        unsigned int oo;              /*    48     4 */
        unsigned int max;             /*    52     4 */
        unsigned int min;             /*    56     4 */
        unsigned int                      allocflags;           /*    60     4 */
        /* --- cacheline 1 boundary (64 bytes) --- */
        int                        refcount;             /*    64     4 */

        /* size: 8408, cachelines: 132, members: 26 */
        /* sum members: 8392, holes: 4, sum holes: 16 */
        /* paddings: 1, sum paddings: 2 */
        /* last cacheline: 24 bytes */
};


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 40960);
    __type(key, u64); // addr
    __type(value, u64); // index: ip+size+priv+zone
} addr2key SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 40960);
    __type(key, u64); 	// ip+size+priv+zone
    __type(value, u64); // cache addr
} key2cache SEC(".maps");

u64 get_key(u64 ip, u32 size, u32 uid, u32 zone)
{
	u64 ret = zone << 59;
	u64 priv = (uid == 0 ? 1 : 0);
	if (priv == 1)
		ret = ret | (1 << 62);
	ret = ret | (size << 31);
	ret = ret & ip;
	return ret;
}

u32 get_size(u32 size)
{
	u32 ret = (size + 4096) / 4096;
	return (ret + 1) * 4096;
}

u32 get_zone(u32 gfp_flags)
{
	u32 ret = 0;
	if (gfp_flags & ___GFP_DMA) {
		ret = 1;
	} else if (gfp_flags & ___GFP_RECLAIMABLE) {
		ret = 2;
	} else if (gfp_flags & ___GFP_ACCOUNT) {
		ret = 3;
	}
	return ret;
}

// ffffffff813371a0 <single_open>:
// ...
// ffffffff813371c5:       e8 e6 ef f9 ff          call   ffffffff812d61b0 <kmem_cache_alloc_trace>        ffffffff813371c6: R_X86_64_PLT32        kmem_cache_alloc_trace-0x4
// ffffffff813371ca:       48 85 c0                test   %rax,%rax

// void *kmem_cache_alloc_trace(struct kmem_cache *s, gfp_t gfpflags, size_t size)
// python3 -c 'print(hex(0xffffffff813371c5-0xffffffff813371a0))'
SEC("kprobe/single_open+0x25")
int BPF_KPROBE(kmem_cache_alloc_trace)
{
    u64 ip = ctx->ip;
	u64 *pv;
	struct kmem_cache *cache = (struct kmem_cache*) ctx->di;
    u64 alloc_size = BPF_CORE_READ(cache, size);
	u32 gfp_flags = (u32) ctx->si;
	u32 uid = bpf_get_current_uid_gid() >> 32;
	u32 zone = get_zone(gfp_flags);
    u64 key = get_key(ip, alloc_size, uid, zone);;
	u64 cache_addr = 0;
    u64 alloc_addr = 0;
	int err = 0; 
    
    
    // if there is a slab cache
    u64 *pcache = bpf_map_lookup_elem(&key2cache, &key);
    bpf_printk("===key: %016lx  %016lx %016lx===\n", key, alloc_size, ctx->di);

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
    } else {
        bpf_printk("===HotBPF isolate single_open %lx===\n", alloc_addr);
    }
    // alloc_addr = 0;

    // add new object to inuse map for free.
    // err = bpf_map_update_elem(&addr2key, &alloc_addr, &key, BPF_ANY);
    // if (err < 0) {
    //     bpf_printk("addr2key update failed: %d\n", err);
    //     return err;
    // }

    
    bpf_jmp_next(ctx, ip + 0x4, alloc_addr);

	return 0;
}


// ffffffff81534d70 <bio_kmalloc>:
// ...
// ffffffff81534d9a:       e8 41 23 da ff          call   ffffffff812d70e0 <__kmalloc>     ffffffff81534d9b: R_X86_64_PLT32        __kmalloc-0x4
// ffffffff81534d9f:       48 85 c0                test   %rax,%rax

// void *__kmalloc(size_t size, gfp_t flags)
// python3 -c 'print(hex(0xffffffff81534d9a-0xffffffff81534d70))'
SEC("kprobe/bio_kmalloc+0x2a")
int BPF_KPROBE(__kmalloc)
{
    u64 ip = ctx->ip;
	u64 *pv;
    u64 alloc_size = get_size(ctx->di);
	u32 gfp_flags = (u32) ctx->si;
	u32 uid = bpf_get_current_uid_gid() >> 32;
	u32 zone = get_zone(gfp_flags);
    u64 key = get_key(ip, alloc_size, uid, zone);;
	u64 cache_addr = 0;
    u64 alloc_addr = 0;
	int err = 0; 
    
    
    // if there is a slab cache
    u64 *pcache = bpf_map_lookup_elem(&key2cache, &key);
    bpf_printk("===key: %016lx  %016lx %016lx===\n", key, alloc_size, ctx->di);

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
    } else {
        bpf_printk("===HotBPF isolate bio_kmalloc %lx===\n", alloc_addr);
    }

    // add new object to inuse map for free.
    // err = bpf_map_update_elem(&addr2key, &alloc_addr, &key, BPF_ANY);
    // if (err < 0) {
    //     bpf_printk("addr2key update failed: %d\n", err);
    //     return err;
    // }

    
    bpf_jmp_next(ctx, ip + 0x4, alloc_addr);

	return 0;
}




// ffffffff813374c0 <single_release>:
// ...
// ffffffff813374ee:       e8 cd bf f9 ff          call   ffffffff812d34c0 <kfree> ffffffff813374ef: R_X86_64_PLT32        kfree-0x4
// ffffffff813374f3:       31 c0                   xor    %eax,%eax

// SEC("kprobe/single_release")
// int BPF_KPROBE(kfree)
// {
//     u64 *pkey = bpf_map_lookup_elem(&addr2key, &alloc_addr);
// 	if (pkey) {
// 		err = bpf_map_delete_elem(&addr2key, &alloc_addr);
// 		if (err < 0) {
// 			bpf_printk("kfree addr2key delete failed: %d\n", err);
// 			return err;
// 		}
//     }
//     return 0;
// }


char LICENSE[] SEC("license") = "Dual BSD/GPL";

