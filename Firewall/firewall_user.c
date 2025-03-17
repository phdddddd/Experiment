// firewall_user.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <net/if.h>

// 此处假设网卡名为 "eth0"，请根据实际情况修改
#define IFACE "eth0"
#define NUM_TESTS 1000

// 用于将禁止 IP 插入到 eBPF 映射中
int insert_banned_ip(int map_fd, const char *ip_str) {
    uint32_t ip;
    if (inet_pton(AF_INET, ip_str, &ip) != 1) {
        fprintf(stderr, "Invalid IP: %s\n", ip_str);
        return -1;
    }
    uint32_t value = 1;
    return bpf_map_update_elem(map_fd, &ip, &value, BPF_ANY);
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    int prog_fd, map_fd;
    int err;

    // 加载 eBPF 程序
    obj = bpf_object__open_file("firewall_kern.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open eBPF object file\n");
        return 1;
    }
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load eBPF object: %d\n", err);
        return 1;
    }
    // 获取 eBPF 程序 fd
    struct bpf_program *prog = bpf_object__find_program_by_title(obj, "xdp_firewall");
    if (!prog) {
        fprintf(stderr, "Failed to find xdp_firewall program\n");
        return 1;
    }
    prog_fd = bpf_program__fd(prog);

    // 附加 eBPF 程序到网卡
    int ifindex = if_nametoindex(IFACE);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }
    err = bpf_set_link_xdp_fd(ifindex, prog_fd, 0);
    if (err < 0) {
        fprintf(stderr, "Failed to attach XDP program: %d\n", err);
        return 1;
    }
    printf("XDP program successfully attached on %s\n", IFACE);

    // 获取禁止 IP 映射的文件描述符
    map_fd = bpf_object__find_map_fd_by_name(obj, "banned_ips_map");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get map fd\n");
        return 1;
    }

    // 插入禁止的 IP 地址（假设有 100 个禁止 IP，示例中使用 "192.168.1.X"）
    char ip_buf[16];
    for (int i = 1; i <= 100; i++) {
        snprintf(ip_buf, sizeof(ip_buf), "192.168.1.%d", i);
        if (insert_banned_ip(map_fd, ip_buf) < 0) {
            fprintf(stderr, "Failed to insert IP %s\n", ip_buf);
        }
    }
    printf("Inserted 100 banned IPs.\n");

    // 模拟查询统计：实际数据包处理在内核中进行，此处仅模拟查询调用
    struct timeval start, end;
    double total_time = 0.0;
    for (int i = 0; i < NUM_TESTS; i++) {
        // 模拟一个查询：我们直接调用 bpf_map_lookup_elem 模拟内核中的查询过程
        uint32_t ip;
        if (inet_pton(AF_INET, "192.168.1.50", &ip) != 1) {
            fprintf(stderr, "Invalid test IP\n");
            return 1;
        }

        gettimeofday(&start, NULL);
        // 模拟查询：这里实际是在内核态完成匹配
        uint32_t *value = bpf_map_lookup_elem(map_fd, &ip);
        gettimeofday(&end, NULL);

        double query_time = (end.tv_sec - start.tv_sec) * 1000.0 +
                            (end.tv_usec - start.tv_usec) / 1000.0;
        total_time += query_time;
    }
    printf("Performed %d simulated queries, average query time: %.6f ms\n", NUM_TESTS, total_time / NUM_TESTS);

    // 清理：卸载 XDP 程序
    bpf_set_link_xdp_fd(ifindex, -1, 0);
    bpf_object__close(obj);
    return 0;
}
