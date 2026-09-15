#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <bpf/bpf.h>
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

    int cgroup_fd = open("/sys/fs/cgroup", O_RDONLY | O_DIRECTORY);
    if (cgroup_fd < 0) {
        perror("Failed to open /sys/fs/cgroup");
        poc_dns_bpf__destroy(skel);
        return 1;
    }

    int connect4_fd = bpf_program__fd(skel->progs.probe_dns_connect4);
    int sendmsg4_fd = bpf_program__fd(skel->progs.probe_dns_sendmsg4);

    // 动态提取 BPF 字节码自带的标准 attach_type，杜绝硬编码枚举错误
    enum bpf_attach_type type_connect4 = bpf_program__expected_attach_type(skel->progs.probe_dns_connect4);
    enum bpf_attach_type type_sendmsg4 = bpf_program__expected_attach_type(skel->progs.probe_dns_sendmsg4);

    int ret_connect = bpf_prog_attach(connect4_fd, cgroup_fd, type_connect4, BPF_F_ALLOW_MULTI);
    if (ret_connect < 0) {
        perror("Failed to attach connect4");
    }

    int ret_sendmsg = bpf_prog_attach(sendmsg4_fd, cgroup_fd, type_sendmsg4, BPF_F_ALLOW_MULTI);
    if (ret_sendmsg < 0) {
        perror("Failed to attach sendmsg4");
    }

    if (ret_connect < 0 && ret_sendmsg < 0) {
        fprintf(stderr, "Failed to attach both hooks\n");
        close(cgroup_fd);
        poc_dns_bpf__destroy(skel);
        return 1;
    }

    printf(">>> B-0 Probe successfully attached via BPF_F_ALLOW_MULTI!\n");
    fflush(stdout);

    while (running) {
        sleep(1);
    }

    printf("\nDetaching hooks...\n");
    if (ret_connect == 0) {
        bpf_prog_detach2(connect4_fd, cgroup_fd, type_connect4);
    }
    if (ret_sendmsg == 0) {
        bpf_prog_detach2(sendmsg4_fd, cgroup_fd, type_sendmsg4);
    }

    close(cgroup_fd);
    poc_dns_bpf__destroy(skel);
    return 0;
}