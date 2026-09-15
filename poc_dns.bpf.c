#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

char LICENSE[] SEC("license") = "GPL";

// 探测应用通过 connect() 显式连接 DNS 53 端口
SEC("cgroup/connect4")
int probe_dns_connect4(struct bpf_sock_addr *ctx)
{
    if (ctx->protocol == IPPROTO_UDP && ctx->user_port == bpf_htons(53)) {
        bpf_printk("[B-0] connect4 hit: UID=%d\n", bpf_get_current_uid_gid() & 0xFFFFFFFF);
    }
    return 1;
}

// 探测应用通过 sendto() 无连接发送 DNS 53 请求
SEC("cgroup/sendmsg4")
int probe_dns_sendmsg4(struct bpf_sock_addr *ctx)
{
    if (ctx->protocol == IPPROTO_UDP && ctx->user_port == bpf_htons(53)) {
        bpf_printk("[B-0] sendmsg4 hit: UID=%d\n", bpf_get_current_uid_gid() & 0xFFFFFFFF);
    }
    return 1;
}