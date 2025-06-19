#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <rdma/ib_verbs.h>

#define MAX_MAPPINGS 1024
#define ROCE_V2_PORT 4791


struct qpn_map_key {
    __u32 remote_ip;
    __u32 local_qpn;
};


struct qpn_map_value {
    __u32 remote_qpn;
};


struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_MAPPINGS);
    __type(key, struct qpn_map_key);
    __type(value, struct qpn_map_value);
} qpn_map SEC(".maps");

SEC("kprobe/ibv_modify_qp")
int trace_ibv_modify_qp(struct pt_regs *ctx)
{
    struct ib_qp *qp = (struct ib_qp *)PT_REGS_PARM1(ctx);
    struct ib_qp_attr *attr = (struct ib_qp_attr *)PT_REGS_PARM2(ctx);
    int attr_mask = (int)PT_REGS_PARM3(ctx);

    if (!(attr_mask & IB_QP_STATE) || attr->qp_state != IB_QPS_RTR) {
        return 0;
    }

    __be32 remote_ip = 0;
    if (attr->ah_attr.grh.dgid.global.interface_id >> 32 == 0x0000ffff) {
        remote_ip = (__be32)(attr->ah_attr.grh.dgid.global.interface_id & 0xFFFFFFFF);
    }


    __u32 local_qpn = qp->qp_num;

    struct qpn_map_key key = {
        .remote_ip = remote_ip,
        .local_qpn = local_qpn
    };
    
    struct qpn_map_value value = {
        .remote_qpn = attr->dest_qp_num
    };
    
    bpf_map_update_elem(&qpn_map, &key, &value, BPF_ANY);
    
    if (qp->qp_num == attr->dest_qp_num) {
        bpf_printk("Security policy violation: src_qpn == dst_qpn (%u)", qp->qp_num);
        return -1; // 阻止非法连接
    }
    
    return 0;
}

SEC("xdp")
int xdp_outbound_handler(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if (eth + 1 > data_end) 
        return XDP_PASS;
    
    if (eth->h_proto != htons(ETH_P_IP)) 
        return XDP_PASS;
    
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if (iph + 1 > data_end)
        return XDP_PASS;
    

    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;
    
    struct udphdr *udph = (struct udphdr *)(iph + 1);
    if (udph + 1 > data_end)
        return XDP_PASS;
    

    if (udph->dest != htons(ROCE_V2_PORT))
        return XDP_PASS;
    
    struct ib_bth *bth = (struct ib_bth *)(udph + 1);
    if (bth + 1 > data_end)
        return XDP_PASS;
    

    struct qpn_map_key key = {
        .remote_ip = iph->daddr,
        .local_qpn = bth->dst_qpn
    };
    

    struct qpn_map_value *value = bpf_map_lookup_elem(&qpn_map, &key);
    if (!value) {
        return XDP_PASS;
    }
    

    bth->dst_qpn = value->remote_qpn;
    
    return XDP_TX;
}


SEC("xdp")
int xdp_inbound_handler(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if (eth + 1 > data_end) 
        return XDP_PASS;
    
    if (eth->h_proto != htons(ETH_P_IP)) 
        return XDP_PASS;
    
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if (iph + 1 > data_end)
        return XDP_PASS;
    
    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;
    
    struct udphdr *udph = (struct udphdr *)(iph + 1);
    if (udph + 1 > data_end)
        return XDP_PASS;
    
    if (udph->dest != htons(ROCE_V2_PORT))
        return XDP_PASS;
    
    struct ib_bth *bth = (struct ib_bth *)(udph + 1);
    if (bth + 1 > data_end)
        return XDP_PASS;
    
    struct qpn_map_key key = {
        .remote_ip = iph->saddr,
        .local_qpn = bth->dst_qpn
    };
    
    struct qpn_map_value *value = bpf_map_lookup_elem(&qpn_map, &key);
    if (!value) {
        return XDP_DROP;
    }
    
    if (value->remote_qpn != bth->dst_qpn) {
        return XDP_DROP;
    }
    
    return XDP_PASS;
}