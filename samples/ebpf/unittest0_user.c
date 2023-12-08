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

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}


struct args {
	int memcg_id;
	int pid;
};


int run_aging(int aging_fd, int memcg_id)
{
	struct args ctx = {
		.memcg_id = memcg_id,
		.pid = 243,
	};
	LIBBPF_OPTS(bpf_test_run_opts, tattr, .ctx_in = &ctx,
		    .ctx_size_in = sizeof(ctx));
	return bpf_prog_test_run_opts(aging_fd, &tattr);
}

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

// cat /sys/kernel/debug/tracing/trace_pipe
int main(int argc, char **argv)
{
    struct bpf_link *links[2];
	struct bpf_program *prog;
	struct bpf_object *obj;
	int memcg_aging_fd;
	char filename[256];
	int j = 0;
	int trace_fd;
	
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

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

    printf("Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	
	printf("start tracing\n");
	
	int c = 1;
	while (!stop) {
		// run_aging(memcg_aging_fd, 2);
		run_active_scan(memcg_aging_fd, 2, 243);
		sleep(120);
	}
	// run_active_scan(memcg_aging_fd, 2, 243);
    while (!stop) {
		// sleep(1);
		// run_aging(memcg_aging_fd, c++);

		// if (c == 10000) goto cleanup;
		// sleep(1);
		
		static char buf[4096];
		ssize_t sz;
		sz = read(trace_fd, buf, sizeof(buf) - 1);
		if (sz > 0) {
			buf[sz] = '\0';
			// printf("trace: %s\n", buf);
			puts(buf);
		}
    }


    cleanup:
		for (j--; j >= 0; j--)
			bpf_link__destroy(links[j]);
	    bpf_object__close(obj);
		close(trace_fd);
        return 0;




    return 0;
}