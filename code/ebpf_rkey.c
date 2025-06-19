#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/rdma/ib_verbs.h>

#define SEC(NAME) __attribute__((section(NAME), used))
#define FEISTEL_ROUNDS 4
#define ROCE_V2_UDP_PORT 4791

struct bpf_map_def SEC("maps") rkey_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1024,
};

// Feistel轮函数
static __always_inline __u16 feistel_round(__u16 input, __u16 round_key) {
    __u16 rotated = ((input << 3) | (input >> 13));
    return (rotated + round_key) & 0xFFFF;
}

// RKey混淆
static __always_inline __u32 obfuscate_rkey(__u32 orig_rkey) {
    __u16 left = orig_rkey >> 16;
    __u16 right = orig_rkey & 0xFFFF;
    __u16 round_key = 0x5A5A; // 固定轮密钥
    
    for (int i = 0; i < FEISTEL_ROUNDS; i++) {
        __u16 temp = right;
        right = left ^ feistel_round(right, round_key);
        left = temp;
    }
    
    return (left << 16) | right;
}

// RKey还原
static __always_inline __u32 deobfuscate_rkey(__u32 obf_rkey) {
    __u16 left = obf_rkey >> 16;
    __u16 right = obf_rkey & 0xFFFF;
    __u16 round_key = 0x5A5A; // 与混淆相同
    
    for (int i = 0; i < FEISTEL_ROUNDS; i++) {
        __u16 temp = left;
        left = right ^ feistel_round(left, round_key);
        right = temp;
    }
    
    return (left << 16) | right;
}

SEC("kprobe/ib_post_send")
int trace_ib_post_send(struct pt_regs *ctx) {
    struct ib_qp *qp = (struct ib_qp *)PT_REGS_PARM1(ctx);
    struct ib_send_wr *wr = (struct ib_send_wr *)PT_REGS_PARM2(ctx);
    
    if (!wr) return 0;
    
    // 遍历发送请求
    struct ib_send_wr *cur = wr;
    while (cur) {
        if (cur->opcode == IB_WR_RDMA_WRITE || cur->opcode == IB_WR_RDMA_READ) {
            // 处理每个散聚元素
            for (int i = 0; i < cur->num_sge; i++) {
                __u32 *orig_rkey = bpf_map_lookup_elem(&rkey_map, &cur->sg_list[i].lkey);
                if (orig_rkey) {
                    // 恢复原始RKey
                    cur->sg_list[i].lkey = *orig_rkey;
                }
            }
        }
        cur = cur->next;
    }
    
    return 0;
}

SEC("kprobe/ib_post_recv")
int trace_ib_post_recv(struct pt_regs *ctx) {
    struct ib_qp *qp = (struct ib_qp *)PT_REGS_PARM1(ctx);
    struct ib_recv_wr *wr = (struct ib_recv_wr *)PT_REGS_PARM2(ctx);
    
    if (!wr) return 0;
    
    // 遍历接收请求
    struct ib_recv_wr *cur = wr;
    while (cur) {
        // 处理每个散聚元素
        for (int i = 0; i < cur->num_sge; i++) {
            __u32 *orig_rkey = bpf_map_lookup_elem(&rkey_map, &cur->sg_list[i].lkey);
            if (orig_rkey) {
                // 恢复原始RKey
                cur->sg_list[i].lkey = *orig_rkey;
            }
        }
        cur = cur->next;
    }
    
    return 0;
}

SEC("kretprobe/ib_alloc_mr")
int trace_ib_alloc_mr(struct pt_regs *ctx) {
    struct ib_mr *mr = (struct ib_mr *)PT_REGS_RC(ctx);
    if (!mr) return 0;
    
    // 创建原始RKey与混淆RKey的映射
    __u32 orig_rkey = mr->rkey;
    __u32 obf_rkey = obfuscate_rkey(orig_rkey);
    
    // 更新映射表
    bpf_map_update_elem(&rkey_map, &obf_rkey, &orig_rkey, BPF_ANY);
    
    // 返回混淆后的RKey
    mr->rkey = obf_rkey;
    
    return 0;
}

SEC("xdp")
int xdp_rkey_handler(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if (eth + 1 > data_end) 
        return XDP_PASS;
    
    // 只处理IPv4流量
    if (eth->h_proto != __constant_htons(ETH_P_IP)) 
        return XDP_PASS;
    
    struct iphdr *ip = (void *)(eth + 1);
    if (ip + 1 > data_end)
        return XDP_PASS;
    
    // 只处理UDP流量
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;
    
    struct udphdr *udp = (void *)(ip + 1);
    if (udp + 1 > data_end)
        return XDP_PASS;
    
    // 只处理RoCEv2流量
    if (udp->dest != __constant_htons(ROCE_V2_UDP_PORT))
        return XDP_PASS;
    
    struct ib_grh *grh = (void *)(udp + 1);
    if (grh + 1 > data_end)
        return XDP_PASS;
    
    struct ib_bth *bth = (void *)(grh + 1);
    if (bth + 1 > data_end)
        return XDP_PASS;
    
    // RDMA读写操作
    if (bth->opcode == IB_OPCODE_UD_SEND_ONLY || 
        bth->opcode == IB_OPCODE_RC_RDMA_READ_REQUEST ||
        bth->opcode == IB_OPCODE_RC_RDMA_WRITE) {
        
        // 获取数据包中的RKey
        __u32 *pkt_rkey;
        if (bth->opcode == IB_OPCODE_UD_SEND_ONLY) {
            struct ib_ud_header *udh = (struct ib_ud_header *)grh;
            pkt_rkey = &udh->lrh[0]; // 简化位置
        } else {
            pkt_rkey = (__u32 *)(bth + 1);
        }
        
        if (pkt_rkey + 1 > data_end)
            return XDP_PASS;
        
        // 还原原始RKey
        __u32 orig_rkey = deobfuscate_rkey(*pkt_rkey);
        
        // 更新数据包
        *pkt_rkey = orig_rkey;
        
        bpf_printk("Restored RKey: 0x%x -> 0x%x\n", *pkt_rkey, orig_rkey);
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";