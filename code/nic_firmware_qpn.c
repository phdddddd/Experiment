#include <rdma/ib_verbs.h>
#include <rdma/roce.h>

struct qpn_mapping {
    u32 local_qpn;
    u32 remote_qpn;
    u32 remote_ip;
    u64 last_used;
    u8 valid;
};

static struct qpn_mapping qpn_cache[1024];
static spinlock_t cache_lock;


void update_qpn_mapping(u32 local_qpn, u32 remote_qpn, u32 remote_ip)
{
    unsigned long flags;
    int free_index = -1;
    
    spin_lock_irqsave(&cache_lock, flags);
    
    for (int i = 0; i < ARRAY_SIZE(qpn_cache); i++) {
        if (!qpn_cache[i].valid) {
            free_index = i;
        } else if (qpn_cache[i].local_qpn == local_qpn &&
                   qpn_cache[i].remote_ip == remote_ip) {
            qpn_cache[i].remote_qpn = remote_qpn;
            qpn_cache[i].last_used = get_jiffies_64();
            spin_unlock_irqrestore(&cache_lock, flags);
            return;
        }
    }
    
    if (free_index != -1) {
        qpn_cache[free_index].local_qpn = local_qpn;
        qpn_cache[free_index].remote_qpn = remote_qpn;
        qpn_cache[free_index].remote_ip = remote_ip;
        qpn_cache[free_index].last_used = get_jiffies_64();
        qpn_cache[free_index].valid = 1;
    }
    
    spin_unlock_irqrestore(&cache_lock, flags);
}

void handle_outbound_packet(struct nfp_net_tx_ring *tx_ring,
                            struct nfp_net_tx_desc *txd,
                            struct nfp_net_tx_buf *txbuf)
{
    struct rte_mbuf *mbuf = txbuf->mbuf;
    struct ib_bth *bth = get_bth(mbuf);
    
    // 查找映射关系
    u32 remote_qpn = find_remote_qpn(mbuf, bth->dst_qpn);
    
    // 替换QPN字段
    bth->dst_qpn = remote_qpn;
    
    // 发送处理
    nic_send_packet(tx_ring, txd, txbuf);
}

void handle_inbound_packet(struct nfp_net_rx_ring *rx_ring,
                           struct nfp_net_rx_desc *rxd,
                           struct nfp_net_rx_buf *rxbuf)
{
    struct rte_mbuf *mbuf = rxbuf->mbuf;
    struct ib_bth *bth = get_bth(mbuf);
    
    // 验证QPN映射
    if (!validate_qpn_mapping(mbuf, bth)) {
        rte_pktmbuf_free(mbuf);
        return;
    }
    
    // 继续处理
    nic_process_packet(rx_ring, rxd, rxbuf);
}

int validate_qpn_mapping(struct rte_mbuf *mbuf, struct ib_bth *bth)
{
    struct iphdr *iph = get_iphdr(mbuf);
    u32 remote_ip = iph->saddr;
    u32 dst_qpn = bth->dst_qpn;
    
    unsigned long flags;
    spin_lock_irqsave(&cache_lock, flags);
    
    // 查找映射关系
    for (int i = 0; i < ARRAY_SIZE(qpn_cache); i++) {
        if (qpn_cache[i].valid &&
            qpn_cache[i].local_qpn == dst_qpn &&
            qpn_cache[i].remote_ip == remote_ip) {
            
            // 更新最后使用时间
            qpn_cache[i].last_used = get_jiffies_64();
            spin_unlock_irqrestore(&cache_lock, flags);
            return 1; // 找到有效映射
        }
    }
    
    spin_unlock_irqrestore(&cache_lock, flags);
    return 0; // 无效映射
}

void cleanup_stale_mappings(void)
{
    unsigned long flags;
    u64 now = get_jiffies_64();
    
    spin_lock_irqsave(&cache_lock, flags);
    
    for (int i = 0; i < ARRAY_SIZE(qpn_cache); i++) {
        if (qpn_cache[i].valid &&
            now - qpn_cache[i].last_used > 60 * HZ) {
            qpn_cache[i].valid = 0;
        }
    }
    
    spin_unlock_irqrestore(&cache_lock, flags);
}

void handle_sriov_context(struct nfp_net *nn, struct rte_mbuf *mbuf)
{
    struct iphdr *iph = get_iphdr(mbuf);
    u8 vf_id = get_vf_id_from_ip(iph->saddr);
    
    if (vf_id > 0 && vf_id < NFP_NET_MAX_VFS) {
        struct nfp_net *vf_nn = nn->vfs[vf_id];
        if (vf_nn) {
            handle_inbound_packet(&vf_nn->rx_rings[0], ...);
        }
    }
}