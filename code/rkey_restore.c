#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <net/ip.h>
#include <linux/udp.h>
#include <rdma/ib_verbs.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("RDMA RKey Randomization Packet Restore");

#define FEISTEL_ROUNDS 4
#define ROCE_V2_UDP_PORT 4791
#define RKEY_MAP_SIZE 1024

DEFINE_HASHTABLE(rkey_map, 10);

struct rkey_entry {
    u32 obf_rkey;
    u32 orig_rkey;
    struct hlist_node node;
};

// Feistel轮函数
static u16 feistel_round(u16 input, u16 round_key) {
    u16 rotated = ((input << 3) | (input >> 13));
    return (rotated + round_key) & 0xFFFF;
}

// RKey还原
static u32 restore_rkey(u32 obf_rkey) {
    u16 left = obf_rkey >> 16;
    u16 right = obf_rkey & 0xFFFF;
    u16 round_key = 0x5A5A; // 与混淆相同

    for (int i = 0; i < FEISTEL_ROUNDS; i++) {
        u16 temp = left;
        left = right ^ feistel_round(left, round_key);
        right = temp;
    }

    return (left << 16) | right;
}

// 处理收到的数据包
static void process_rdma_packet(struct sk_buff *skb) {
    struct udphdr *udph;
    struct iphdr *iph = ip_hdr(skb);
    
    // UDP头检查
    if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct udphdr)))
        return;
    
    udph = (struct udphdr *)(skb->data + iph->ihl * 4);
    
    // 只处理RoCEv2流量
    if (udph->dest != htons(ROCE_V2_UDP_PORT))
        return;
    
    // RDMA基本传输头
    struct ib_bth *bth = (struct ib_bth *)(udph + 1);
    if (!pskb_may_pull(skb, (u8 *)(bth + 1) - skb->data))
        return;
    
    // RDMA读写操作
    u8 opcode = bth->opcode;
    if (opcode != IB_OPCODE_UD_SEND_ONLY && 
        opcode != IB_OPCODE_RC_RDMA_READ_REQUEST &&
        opcode != IB_OPCODE_RC_RDMA_WRITE) {
        return;
    }
    
    u32 *pkt_rkey;
    if (opcode == IB_OPCODE_UD_SEND_ONLY) {
        struct ib_ud_header *udh = (struct ib_ud_header *)(udph + 1);
        pkt_rkey = &udh->lrh[0]; // 简化位置
    } else {
        pkt_rkey = (u32 *)(bth + 1);
    }
    
    if (!pskb_may_pull(skb, (u8 *)(pkt_rkey + 1) - skb->data))
        return;
    
    u32 orig_rkey;
    struct rkey_entry *entry;
    
    // 查找映射表
    hash_for_each_possible(rkey_map, entry, node, *pkt_rkey) {
        if (entry->obf_rkey == *pkt_rkey) {
            orig_rkey = entry->orig_rkey;
            goto found;
        }
    }
    
    // 如果没找到，尝试还原
    orig_rkey = restore_rkey(*pkt_rkey);
    
    // 缓存结果
    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (entry) {
        entry->obf_rkey = *pkt_rkey;
        entry->orig_rkey = orig_rkey;
        hash_add(rkey_map, &entry->node, entry->obf_rkey);
    }
    
found:
    // 替换包中的rkey
    *pkt_rkey = orig_rkey;
    
    printk(KERN_INFO "Restored RKey: 0x%x -> 0x%x\n", *pkt_rkey, orig_rkey);
}

// Netfilter钩子函数
static unsigned int nf_hook(void *priv, struct sk_buff *skb,
                            const struct nf_hook_state *state) {
    struct iphdr *iph;
    
    if (!skb || !skb->data)
        return NF_ACCEPT;
    
    if (skb->protocol != htons(ETH_P_IP))
        return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;
    
    // 只处理UDP流量
    if (iph->protocol == IPPROTO_UDP) {
        process_rdma_packet(skb);
    }
    
    return NF_ACCEPT;
}

// Netfilter钩子结构
static struct nf_hook_ops nf_ops = {
    .hook = nf_hook,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

// 模块初始化
static int __init rkey_restore_init(void) {
    // 初始化哈希表
    hash_init(rkey_map);
    
    // 注册Netfilter钩子
    nf_register_net_hook(&init_net, &nf_ops);
    
    printk(KERN_INFO "RDMA RKey Restore module loaded\n");
    return 0;
}

// 模块退出
static void __exit rkey_restore_exit(void) {
    // 清理哈希表
    struct rkey_entry *entry;
    struct hlist_node *tmp;
    int bkt;
    
    hash_for_each_safe(rkey_map, bkt, tmp, entry, node) {
        hash_del(&entry->node);
        kfree(entry);
    }
    
    // 注销Netfilter钩子
    nf_unregister_net_hook(&init_net, &nf_ops);
    
    printk(KERN_INFO "RDMA RKey Restore module unloaded\n");
}

module_init(rkey_restore_init);
module_exit(rkey_restore_exit);