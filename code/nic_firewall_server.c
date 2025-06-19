#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>

#define MAX_RULES 1024
#define BATCH_SIZE 32
#define HASH_TABLE_SIZE 1024

// 防火墙规则结构
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t action;  // 0: ALLOW, 1: BLOCK
} firewall_rule_t;

// 快速匹配结构
struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
};

// 规则哈希表
static struct rte_hash *rules_hash = NULL;

// 初始化哈希表
int init_rules_table() {
    struct rte_hash_parameters params = {
        .name = "fw_rules",
        .entries = MAX_RULES,
        .key_len = sizeof(struct flow_key),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
    };
    
    rules_hash = rte_hash_create(&params);
    if (!rules_hash) {
        return -1;
    }
    
    return 0;
}

// 添加规则到哈希表
int add_rule(const firewall_rule_t *rule) {
    struct flow_key key = {
        .src_ip = rule->src_ip,
        .dst_ip = rule->dst_ip,
        .src_port = rule->src_port,
        .dst_port = rule->dst_port,
        .protocol = rule->protocol
    };
    
    const uint8_t *action = &rule->action;
    return rte_hash_add_key_data(rules_hash, &key, (void *)(uintptr_t)*action);
}

// 处理数据包
static void process_packet(struct rte_mbuf *mbuf) {
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    
    // 只处理IPv4包
    if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
        return;
    }
    
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    struct flow_key key = {
        .src_ip = ip->src_addr,
        .dst_ip = ip->dst_addr,
        .protocol = ip->next_proto_id
    };
    
    // 处理传输层协议
    if (ip->next_proto_id == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
        key.src_port = tcp->src_port;
        key.dst_port = tcp->dst_port;
    } else if (ip->next_proto_id == IPPROTO_UDP) {
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip + 1);
        key.src_port = udp->src_port;
        key.dst_port = udp->dst_port;
    }
    
    // 规则匹配
    uintptr_t action_data;
    int ret = rte_hash_lookup_data(rules_hash, &key, (void **)&action_data);
    
    if (ret >= 0) {
        uint8_t action = (uint8_t)action_data;
        if (action == 1) {  // BLOCK
            rte_pktmbuf_free(mbuf);
            return;
        }
    }
    
    // 转发正常流量
    rte_eth_tx_burst(0, 0, &mbuf, 1);
}

// 网卡处理主循环
void process_packets() {
    while (1) {
        struct rte_mbuf *mbufs[BATCH_SIZE];
        uint16_t nb_rx = rte_eth_rx_burst(0, 0, mbufs, BATCH_SIZE);
        
        if (nb_rx == 0) {
            rte_delay_us(1);
            continue;
        }
        
        for (uint16_t i = 0; i < nb_rx; i++) {
            process_packet(mbufs[i]);
        }
    }
}

// 规则更新处理
void handle_rule_updates() {
    int nic_fd = open("/dev/nfp_firewall", O_RDONLY);
    if (nic_fd < 0) {
        perror("Failed to open NIC device");
        return;
    }
    
    struct rte_hash_parameters params = {
        .name = "fw_rules_tmp",
        .entries = MAX_RULES,
        .key_len = sizeof(struct flow_key),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
    };
    
    struct rte_hash *temp_hash = rte_hash_create(&params);
    if (!temp_hash) {
        close(nic_fd);
        return;
    }
    
    while (1) {
        firewall_rule_t rules[MAX_RULES + 1];
        ssize_t bytes_read = read(nic_fd, rules, sizeof(rules));
        
        if (bytes_read <= 0) {
            usleep(100000); // 100ms
            continue;
        }
        
        int count = bytes_read / sizeof(firewall_rule_t);
        if (count == 0) continue;
        
        // 第一条为规则计数
        int rule_count = rules[0].dst_ip;
        
        // 创建临时哈希表
        for (int i = 1; i <= rule_count; i++) {
            struct flow_key key = {
                .src_ip = rules[i].src_ip,
                .dst_ip = rules[i].dst_ip,
                .src_port = rules[i].src_port,
                .dst_port = rules[i].dst_port,
                .protocol = rules[i].protocol
            };
            
            rte_hash_add_key_data(temp_hash, &key, 
                                (void *)(uintptr_t)rules[i].action);
        }
        
        // 原子替换哈希表
        struct rte_hash *old_hash = rules_hash;
        rules_hash = temp_hash;
        
        // 销毁旧表
        rte_hash_free(old_hash);
        
        printf("Updated firewall rules: %d rules\n", rule_count);
        
        // 准备下一个临时表
        temp_hash = rte_hash_create(&params);
        if (!temp_hash) {
            rules_hash = old_hash;  // 回滚
            break;
        }
    }
    
    close(nic_fd);
    if (temp_hash) rte_hash_free(temp_hash);
}

int main(int argc, char *argv[]) {
    // 初始化DPDK环境
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Failed to initialize EAL\n");
    }
    
    // 初始化规则表
    if (init_rules_table() < 0) {
        rte_exit(EXIT_FAILURE, "Failed to create rules hash table\n");
    }
    
    // 创建处理线程
    rte_eal_mp_remote_launch(process_packets, NULL, CALL_MASTER);
    
    // 在主核心上处理规则更新
    handle_rule_updates();
    
    // 清理
    rte_eal_cleanup();
    return 0;
}