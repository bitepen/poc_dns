#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "poc_dns.skel.h"

// 补齐 cgroup attach 类型定义以防头文件版本差异
#ifndef BPF_CGROUP_INET4_CONNECT
#define BPF_CGROUP_INET4_CONNECT 9
#endif

#ifndef BPF_CGROUP_UDP4_SENDMSG
#define BPF_CGROUP_UDP4_SENDMSG 19
#endif

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

    int cgroup_fd = open("/sys/fs/cgroup", O_RDONLY);
    if (cgroup_fd < 0) {
        perror("Failed to open /sys/fs/cgroup");
        poc_dns_bpf__destroy(skel);
        return 1;
    }

    int connect4_fd = bpf_program__fd(skel->progs.probe_dns_connect4);
    int sendmsg4_fd = bpf_program__fd(skel->progs.probe_dns_sendmsg4);

    // 核心改动：采用 BPF_F_ALLOW_MULTI 挂载，与 Android netd 共享 cgroup
    int ret_connect = bpf_prog_attach(connect4_fd, cgroup_fd, BPF_CGROUP_INET4_CONNECT, BPF_F_ALLOW_MULTI);
    if (ret_connect < 0) {
        perror("Failed to attach connect4 (BPF_F_ALLOW_MULTI)");
    }

    int ret_sendmsg = bpf_prog_attach(sendmsg4_fd, cgroup_fd, BPF_CGROUP_UDP4_SENDMSG, BPF_F_ALLOW_MULTI);
    if (ret_sendmsg < 0) {
        perror("Failed to attach sendmsg4 (BPF_F_ALLOW_MULTI)");
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

    // 退出时精准解挂，不破坏系统原生钩子
    printf("\nDetaching hooks...\n");
    if (ret_connect == 0) {
        bpf_prog_detach2(connect4_fd, cgroup_fd, BPF_CGROUP_INET4_CONNECT);
    }
    if (ret_sendmsg == 0) {
        bpf_prog_detach2(sendmsg4_fd, cgroup_fd, BPF_CGROUP_UDP4_SENDMSG);
    }

    close(cgroup_fd);
    poc_dns_bpf__destroy(skel);
    return 0;
}