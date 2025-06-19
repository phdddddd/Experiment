#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>

/* XDP 程序：打印日志后放行数据包 */
SEC("xdp")
int xdp_prog_hello(struct xdp_md *ctx) {
    bpf_printk("Hello from XDP!\n");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

