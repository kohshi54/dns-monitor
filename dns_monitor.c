#include <bpf/libbpf.h>
#include <stdio.h>
#include <unistd.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>

static volatile int stopflg = 0;

static void	signal_handler(int signum, siginfo_t *info, void *context) {
	if (signum == SIGINT) {
		stopflg = 1;
	}
}

void set_sigaction(struct sigaction *act, void (*signal_handler)(int signum, siginfo_t *info, void *context)) {
	bzero(act, sizeof(*act));
	sigemptyset(&(act->sa_mask));
	sigaddset(&(act->sa_mask), SIGINT);
	act->sa_flags = SA_SIGINFO;
	act->sa_sigaction = signal_handler;
	sigaction(SIGINT, act, NULL);
}

int main(void) {
	struct sigaction act;
	struct bpf_tc_hook hook = {};
	struct bpf_tc_opts attach_opts = {};
	int ifindex = if_nametoindex("enp6s18");
	if (!ifindex) {
		perror("if_nametoindex");
		return 1;
	}
	
	struct bpf_object *obj = bpf_object__open_file("dns_monitor.bpf.o", NULL);
	if (!obj) {
		fprintf(stderr, "failed to open BPf object\n");
		return 1;
	}
	
	if (bpf_object__load(obj)) {
		fprintf(stderr, "failed to load BPf object\n");
		bpf_object__close(obj);
		return 1;
	}
	
	struct bpf_program *prog = bpf_object__find_program_by_title(obj, "classifier");
	if (!prog) {
		fprintf(stderr, "failed to find program\n");
		bpf_object__close(obj);
		return 1;
	}
	
	int prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		fprintf(stderr, "failed to get program fd\n");
		bpf_object__close(obj);
		return 1;
	}
	
	memset(&hook, 0, sizeof(hook));
	hook.sz = sizeof(hook);
	hook.ifindex = ifindex;
	hook.attach_point = BPF_TC_EGRESS;
	
	if (bpf_tc_hook_create(&hook)) {
		fprintf(stderr, "failed to create tc hook\n");
		bpf_object__close(obj);
		return 1;
	}
	
	memset(&attach_opts, 0, sizeof(attach_opts));
	attach_opts.sz = sizeof(attach_opts);
	attach_opts.prog_fd = prog_fd;
	//attach_opts.flags = BPf_TC_f_REPLACE;
	//attach_opts.priority = 1;
	
	if (bpf_tc_attach(&hook, &attach_opts)) {
		fprintf(stderr, "failed to attach tc filter\n");
		bpf_tc_hook_destroy(&hook);
		bpf_object__close(obj);
		return 1;
	}
	
	printf("monitor attached on tc\n");
	
	set_sigaction(&act, signal_handler);

	struct bpf_map *map = bpf_object__find_map_by_name(obj, "domain_cnt");
	int map_fd = bpf_map__fd(map);
	while (!stopflg)
	{
		char prev_key[255] = {0};
		char cur_key[255] = {0};
		write(2, "=====\n", 6);
		while (1)
		{
			int err;
			if (prev_key[0] == 0)
				err = bpf_map_get_next_key(map_fd, NULL, &cur_key);
			else
				err = bpf_map_get_next_key(map_fd, &prev_key, &cur_key);
			if (err)
				break;

			int value = 0;
			err = bpf_map_lookup_elem(map_fd, &cur_key, &value);
			if (err == 0) {
				printf("%s=%d\n", cur_key, value);
			}
			memcpy(prev_key, cur_key, 255);
		}
		sleep(2);
	}
	
	attach_opts.prog_fd = 0;
	attach_opts.prog_id = 0;
	if (bpf_tc_detach(&hook, &attach_opts)) {
		perror("bpf_tc_detach");
		fprintf(stderr, "failed to detach tc filter\n");
	} else {
		printf("dns monitor detached\n");
	}

	hook.attach_point = BPF_TC_INGRESS|BPF_TC_EGRESS;
	if (bpf_tc_hook_destroy(&hook)) {
		perror("bpf_tc_hook_destroy");
		fprintf(stderr, "failed to destroy tc hook\n");
	}
	
	bpf_object__close(obj);
	return 0;
}

