#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <fcntl.h>
#include <time.h>

#define VM_READ		0x00000001	/* currently active flags */
#define VM_WRITE	0x00000002
#define VM_EXEC		0x00000004
#define VM_SHARED	0x00000008

static volatile sig_atomic_t stop;
int scan_interval = 0;
int memcg_aging_fd;
int target_pid;
int rb_fd = 0;
int scan_times = 0;
int trace_fd;
FILE *f_sample;

struct event
{
	char id[128];
	unsigned long start;
	unsigned long end;
	unsigned long addr;
	unsigned long pteprot;
	unsigned long vm_flags;
	int ispmd;
	int accessed;
	int index;
};


static void sig_int(int signo)
{
	stop = 1;
}


struct args {
	int memcg_id;
	int pid;
};



int run_active_scan(int scan_fd, int memcg_id, int pid)
{
	struct args ctx = {
		.memcg_id = memcg_id,
		.pid = pid,
	};
	LIBBPF_OPTS(bpf_test_run_opts, tattr, .ctx_in = &ctx,
		    .ctx_size_in = sizeof(ctx));
	return bpf_prog_test_run_opts(scan_fd, &tattr);
}

void poll()
{
	while (!stop) {
		run_active_scan(memcg_aging_fd, 2, target_pid);
		sleep(scan_interval);
		++scan_times;
	}
}

void trace_output()
{
	char buf[4096];

    while (!stop) {
        ssize_t sz;
		sz = read(trace_fd, buf, sizeof(buf) - 1);
		if (sz > 0) {
			buf[sz] = '\0';
			puts(buf);
		}
    }
}

static int handle_rb(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = (struct event *) data;

	// skip list
	// 1. remove shared
	if (e->vm_flags & VM_SHARED) return 0;
	// 2. remove ro
	if ((e->vm_flags & VM_READ) && !((e->vm_flags & VM_EXEC) || (e->vm_flags & VM_WRITE))) return 0;
	// 3. remove .so
	if (strstr(e->id, ".so") != NULL) return 0;
	// 4. remove vdso
	if (strstr(e->id, "anon-") != NULL && (e->vm_flags & VM_EXEC)) return 0;

	unsigned long pteprot = e->pteprot & (unsigned long) 0xffff000000000fff;

	// printf("%d, %s, %016lx, %d, %d\n", scan_times, e->id, e->addr, e->index, e->accessed);
	fprintf(f_sample, "%d,%s,%016lx,%016lx,%016lx,%d,%016lx,%016lx,%d\n", scan_times, e->id, e->addr, e->start, e->end, e->index, pteprot, e->vm_flags, e->accessed);
	return 0;
}

// cat /sys/kernel/debug/tracing/trace_pipe
int main(int argc, char **argv)
{
    struct bpf_link *links[2];
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct ring_buffer *rb = NULL;
	int err = 0;
	
	char filename[256];
	int j = 0;
	

	if (argc < 3) {
		printf("usage: ./xxx <pid> <sampling interval(sec)>\n");
		return -1;
	}

	target_pid = atoi(argv[1]);
	scan_interval = atoi(argv[2]);

	struct rlimit limit;
  
	limit.rlim_cur = 65535;
	limit.rlim_max = 65535;
	if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
		printf("setrlimit() failed with errno=%d\n", errno);
		return 1;
	}
	
	trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0) {
		printf("cannot open trace_pipe %d\n", trace_fd);
		// return trace_fd;
	}

    snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 0;
	}

	/* load BPF program */
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}


	bpf_object__for_each_program(prog, obj) {
		char *prog_name = bpf_program__name(prog);
		if (strncmp(prog_name, "memcg_run_aging", 15) == 0) {
			memcg_aging_fd = bpf_program__fd(prog);
			continue;
		}
		links[j] = bpf_program__attach(prog);
		if (libbpf_get_error(links[j])) {
			fprintf(stderr, "ERROR: bpf_program__attach failed\n");
			printf("attach failed: %016lx, %s\n", prog, bpf_program__name(prog));
			links[j] = NULL;
			goto cleanup;
		}
		j++;
	}

	rb_fd = bpf_object__find_map_fd_by_name(obj, "rb");
	rb = ring_buffer__new(rb_fd, handle_rb, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	time_t rawtime;
	struct tm * timeinfo;

	time ( &rawtime );
	timeinfo = localtime ( &rawtime );
	char timebuf[80];
	strftime(timebuf, sizeof(timebuf), "%Y-%m-%d-%H-%M", timeinfo);
	snprintf(filename, sizeof(filename), "sample-%dsec-%s.csv", scan_interval, timebuf);
	f_sample = fopen(filename, "w");
	if (f_sample == NULL) {
		fprintf(stderr, "Failed to create f_sample_file\n");
		goto cleanup;
	}

    printf("Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	pthread_t thread0;
    if (pthread_create(&thread0, NULL, trace_output, NULL) != 0) {
        perror("Failed to create thread");
        return 1;
    }
	pthread_detach(thread0, NULL);
	printf("start tracing\n");

	pthread_t thread;
    if (pthread_create(&thread, NULL, poll, NULL) != 0) {
        perror("Failed to create thread");
        return 1;
    }
    pthread_detach(thread, NULL);
	
	
	// run_active_scan(memcg_aging_fd, 2, 243);
    while (!stop) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		if (err == -EINTR) {
 			err = 0;
 			break;
 		}
 		if (err < 0) {
 			printf("Error polling ring buffer: %d\n", err);
 			break;
 		}
    }


cleanup:
	for (j--; j >= 0; j--)
		bpf_link__destroy(links[j]);
	bpf_object__close(obj);
	close(trace_fd);
	close(f_sample);
	return 0;




    return 0;
}