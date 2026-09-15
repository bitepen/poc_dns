#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "poc_dns.skel.h"

static volatile int running = 1;
static void sig_handler(int sig) { running = 0; }

int main()
{
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct poc_dns_bpf *skel = poc_dns_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load skeleton\n");
        return 1;
    }

    // Android 15 的统一根 cgroup
    int cgroup_fd = open("/sys/fs/cgroup", O_RDONLY);
    if (cgroup_fd < 0) {
        perror("Failed to open /sys/fs/cgroup");
        poc_dns_bpf__destroy(skel);
        return 1;
    }

    skel->links.probe_dns_connect4 = bpf_program__attach_cgroup(skel->progs.probe_dns_connect4, cgroup_fd);
    skel->links.probe_dns_sendmsg4 = bpf_program__attach_cgroup(skel->progs.probe_dns_sendmsg4, cgroup_fd);

    if (!skel->links.probe_dns_connect4 || !skel->links.probe_dns_sendmsg4) {
        fprintf(stderr, "Failed to attach cgroup hooks\n");
        close(cgroup_fd);
        poc_dns_bpf__destroy(skel);
        return 1;
    }

    printf(">>> B-0 Probe running. Target: /sys/fs/cgroup\n");
    fflush(stdout);

    while (running) {
        sleep(1);
    }

    printf("\nExiting and detaching...\n");
    close(cgroup_fd);
    poc_dns_bpf__destroy(skel);
    return 0;
}