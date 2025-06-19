#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <jansson.h>

// ==========================
// 配置参数
// ==========================
// A1阈值
#define A1_THRESH_REQ 1000
#define A1_THRESH_RTU_RATIO 0.1

// A2阈值
#define A2_DELTA_THRESH 100
#define A2_TOTAL_THRESH 16000

// A3阈值
#define A3_TOTAL_THRESH 5000
#define A3_SINGLE_THRESH 300
#define A3_CYCLE_THRESH 3

// A4/A5/A6阈值
#define A456_PSN_ANOMALY_THRESH 10
#define A456_QPN_GUESS_RATE 0.3

// A7阈值
#define A7_PATTERN_THRESH 10

// A8阈值
#define A8_REPLAY_THRESH 5

// A9阈值
#define A9_INTRA_GROUP_THRESH 0.0001
#define A9_WINDOW_SIZE 16


// IP和QPN映射
typedef struct {
    uint32_t qpn;
    char ip[16];
} QPN_IP_Mapping;

QPN_IP_Mapping qpn_ip_mappings[1000];
int mapping_count = 0;

// 计数器状态
typedef struct {
    uint64_t cm_rx_req;
    uint64_t cm_tx_rtu;
    uint64_t rx_read_req;
    uint64_t rx_write_req;
    uint64_t out_of_seq;
    uint64_t dup_req;
} CounterMetrics;

CounterMetrics prev_metrics = {0};

// 攻击检测的状态
typedef struct {
    uint32_t ip;
    int count;
    int cycles;
} A3_State;

A3_State a3_states[100];
int a3_state_count = 0;

// 包捕获统计
typedef struct {
    uint32_t source_ip;
    uint32_t destination_ip;
    uint32_t qpn;
    time_t timestamp;
    uint32_t opcode;
    uint32_t psn;
    uint32_t ack_req;  // 用于ACK标志
} PacketInfo;

PacketInfo captured_packets[1000];
int packet_count = 0;

// 黑名单和通知状态
uint32_t blacklist[100];
int blacklist_count = 0;
time_t last_notification = 0;

pthread_mutex_t data_mutex = PTHREAD_MUTEX_INITIALIZER;

void log_message(const char *level, const char *message) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    printf("[%s][%02d:%02d:%02d] %s\n", level, t->tm_hour, t->tm_min, t->tm_sec, message);
}

uint64_t read_hw_counter(const char *path) {
    FILE *file = fopen(path, "r");
    if (!file) {
        log_message("WARN", "无法读取硬件计数器");
        return 0;
    }
    
    uint64_t value;
    if (fscanf(file, "%lu", &value) != 1) {
        log_message("WARN", "计数器格式错误");
        value = 0;
    }
    
    fclose(file);
    return value;
}

char* run_command(const char *command) {
    FILE *fp = popen(command, "r");
    if (!fp) {
        perror("popen失败");
        return NULL;
    }

    char *result = malloc(4096);
    if (!result) {
        pclose(fp);
        return NULL;
    }

    size_t len = 0;
    char *line = NULL;
    while (fgets(result + len, 4096 - len, fp) != NULL) {
        len = strlen(result);
        if (len >= 4096 - 1) break;
    }

    pclose(fp);
    return result;
}

int get_current_qp_count() {
    char *output = run_command("rdma res -j");
    if (!output) {
        return -1;
    }

    json_t *root;
    json_error_t error;
    root = json_loads(output, 0, &error);
    free(output);

    if (!root) {
        log_message("ERROR", "解析rdma res输出失败");
        return -1;
    }

    int qp_count = 0;
    if (json_is_array(root)) {
        size_t index;
        json_t *value;
        json_array_foreach(root, index, value) {
            json_t *qp_field = json_object_get(value, "qp");
            if (json_is_integer(qp_field)) {
                qp_count += json_integer_value(qp_field);
            }
        }
    }

    json_decref(root);
    return qp_count;
}

void update_qp_mappings() {
    char *output = run_command("rdma link");
    if (!output) {
        return;
    }

    // 解析命令输出格式(简化处理)
    char *line = strtok(output, "\n");
    pthread_mutex_lock(&data_mutex);
    mapping_count = 0;
    
    while (line) {
        char dev[64], src[64], dst[64];
        int qpn;
        
        // 尝试解析rdma link的输出行
        if (sscanf(line, "%*s %*d %s %*d %s %*s %s qpn %d", dev, src, dst, &qpn) == 4) {
            strcpy(qpn_ip_mappings[mapping_count].ip, src);
            qpn_ip_mappings[mapping_count].qpn = qpn;
            mapping_count++;
        }
        
        line = strtok(NULL, "\n");
    }
    
    pthread_mutex_unlock(&data_mutex);
    free(output);
    
    char log_msg[128];
    snprintf(log_msg, sizeof(log_msg), "更新QP映射: %d个活动QP链接", mapping_count);
    log_message("INFO", log_msg);
}

void detect_A1(CounterMetrics current_metrics) {
    uint64_t delta_req = current_metrics.cm_rx_req - prev_metrics.cm_rx_req;
    uint64_t delta_rtu = current_metrics.cm_tx_rtu - prev_metrics.cm_tx_rtu;
    
    if (delta_req > A1_THRESH_REQ) {
        double ratio = (delta_req > 0) ? (double)delta_rtu / delta_req : 0.0;
        if (ratio < A1_THRESH_RTU_RATIO) {
            log_message("ALERT", "A1检测: 连接洪泛攻击可能发生");
        }
    }
}

void detect_A2(int current_qp, int prev_qp) {
    int delta_qp = current_qp - prev_qp;
    
    if (delta_qp > A2_DELTA_THRESH || current_qp > A2_TOTAL_THRESH) {
        char log_msg[128];
        snprintf(log_msg, sizeof(log_msg), 
                "A2检测: QP异常变化 ΔQP=%d, 当前QP=%d", delta_qp, current_qp);
        log_message("ALERT", log_msg);
    }
}

void detect_A3() {
    pthread_mutex_lock(&data_mutex);
    
    // 计算总请求数
    uint64_t total_reqs = 0;
    for (int i = 0; i < a3_state_count; i++) {
        total_reqs += a3_states[i].count;
    }
    
    // 检测A3攻击
    if (total_reqs > A3_TOTAL_THRESH) {
        for (int i = 0; i < a3_state_count; i++) {
            if (a3_states[i].count > A3_SINGLE_THRESH) {
                a3_states[i].cycles++;
                if (a3_states[i].cycles >= A3_CYCLE_THRESH) {
                    char msg[100];
                    snprintf(msg, sizeof(msg), "A3检测: IP %u.%u.%u.%u 资源DoS攻击",
                            (a3_states[i].ip >> 24) & 0xFF,
                            (a3_states[i].ip >> 16) & 0xFF,
                            (a3_states[i].ip >> 8) & 0xFF,
                            a3_states[i].ip & 0xFF);
                    log_message("ALERT", msg);
                    
                    // 重置计数器
                    a3_states[i].count = 0;
                    a3_states[i].cycles = 0;
                }
            }
        }
    }
    
    pthread_mutex_unlock(&data_mutex);
}

void detect_A456() {
    pthread_mutex_lock(&data_mutex);
    
    // 统计序列异常和重复请求
    uint32_t invalid_qpn_count = 0;
    uint32_t suspicious_ips[10] = {0};
    uint32_t ip_counts[10] = {0};
    
    // 分析最近的包
    for (int i = 0; i < packet_count; i++) {
        PacketInfo pkt = captured_packets[i];
        
        // 检查QPN是否有效
        int valid_qpn = 0;
        for (int j = 0; j < mapping_count; j++) {
            if (pkt.qpn == qpn_ip_mappings[j].qpn) {
                valid_qpn = 1;
                break;
            }
        }
        
        // 检测序列号异常 (A4/A5)
        if (i > 0) {
            uint32_t prev_psn = captured_packets[i-1].psn;
            if (abs((int)(pkt.psn - prev_psn)) > 10000) { // 简单跳跃检测
                if (!valid_qpn) invalid_qpn_count++;
            }
        }
        
        // 检测重复请求 (A6)
        if (i > 1 && 
            pkt.psn == captured_packets[i-1].psn && 
            pkt.psn == captured_packets[i-2].psn) {
            if (!valid_qpn) invalid_qpn_count++;
        }
        
        // 记录可疑IP
        if (!valid_qpn) {
            for (int j = 0; j < 10; j++) {
                if (suspicious_ips[j] == 0) {
                    suspicious_ips[j] = pkt.source_ip;
                    ip_counts[j] = 1;
                    break;
                } else if (suspicious_ips[j] == pkt.source_ip) {
                    ip_counts[j]++;
                    break;
                }
            }
        }
    }
    
    // 检测QPN猜测攻击
    if (packet_count > 0) {
        double rate = (double)invalid_qpn_count / packet_count;
        if (rate > A456_QPN_GUESS_RATE) {
            // 找最可疑的IP
            uint32_t max_ip = 0;
            int max_count = 0;
            for (int j = 0; j < 10; j++) {
                if (ip_counts[j] > max_count) {
                    max_count = ip_counts[j];
                    max_ip = suspicious_ips[j];
                }
            }
            
            if (max_ip) {
                char msg[128];
                uint8_t *ip = (uint8_t*)&max_ip;
                snprintf(msg, sizeof(msg), 
                        "A4/A5/A6检测: IP %d.%d.%d.%d PSN注入攻击 (异常率%.2f)", 
                        ip[3], ip[2], ip[1], ip[0], rate);
                log_message("ALERT", msg);
            }
        }
    }
    
    pthread_mutex_unlock(&data_mutex);
}

void detect_A7() {
    pthread_mutex_lock(&data_mutex);
    
    // 检测稳定的时间模式
    for (int i = 0; i < mapping_count; i++) {
        uint32_t ip = ip_to_int(qpn_ip_mappings[i].ip);
        uint64_t total_pkts = 0;
        uint64_t timed_pkts = 0;
        
        for (int j = 0; j < packet_count; j++) {
            if (captured_packets[j].source_ip == ip) {
                total_pkts++;
                
                // 检测稳定的间隔模式
                if (j > 0) {
                    double interval = difftime(captured_packets[j].timestamp, 
                                             captured_packets[j-1].timestamp);
                    if (interval > 0.0001 && interval < 0.0003) { // 100-300μs
                        timed_pkts++;
                    }
                }
            }
        }
        
        if (total_pkts > A7_PATTERN_THRESH && 
            (double)timed_pkts / total_pkts > 0.8) {
            char msg[128];
            snprintf(msg, sizeof(msg), "A7检测: IP %s 基于时间的侧信道攻击", 
                    qpn_ip_mappings[i].ip);
            log_message("ALERT", msg);
        }
    }
    
    pthread_mutex_unlock(&data_mutex);
}

void detect_A8() {
    pthread_mutex_lock(&data_mutex);
    
    // 检测重放攻击
    uint32_t replay_count = 0;
    uint32_t suspicious_ips[10] = {0};
    uint32_t ip_counts[10] = {0};
    
    // 检查连续的相同数据包
    for (int i = 2; i < packet_count; i++) {
        PacketInfo pkt1 = captured_packets[i-2];
        PacketInfo pkt2 = captured_packets[i-1];
        PacketInfo pkt3 = captured_packets[i];
        
        if (pkt1.source_ip == pkt2.source_ip && 
            pkt2.source_ip == pkt3.source_ip &&
            pkt1.destination_ip == pkt2.destination_ip && 
            pkt2.destination_ip == pkt3.destination_ip &&
            pkt1.qpn == pkt2.qpn && 
            pkt2.qpn == pkt3.qpn &&
            pkt1.psn == pkt2.psn && 
            pkt2.psn == pkt3.psn) {
            
            replay_count++;
            
            // 记录可疑IP
            for (int j = 0; j < 10; j++) {
                if (suspicious_ips[j] == 0) {
                    suspicious_ips[j] = pkt1.source_ip;
                    ip_counts[j] = 1;
                    break;
                } else if (suspicious_ips[j] == pkt1.source_ip) {
                    ip_counts[j]++;
                    break;
                }
            }
        }
    }
    
    // 检测A8攻击
    if (replay_count > A8_REPLAY_THRESH) {
        // 找最可疑的IP
        uint32_t max_ip = 0;
        int max_count = 0;
        for (int j = 0; j < 10; j++) {
            if (ip_counts[j] > max_count) {
                max_count = ip_counts[j];
                max_ip = suspicious_ips[j];
            }
        }
        
        if (max_ip) {
            char msg[128];
            uint8_t *ip = (uint8_t*)&max_ip;
            snprintf(msg, sizeof(msg), "A8检测: IP %d.%d.%d.%d 重放攻击 (%d次重放)", 
                    ip[3], ip[2], ip[1], ip[0], replay_count);
            log_message("ALERT", msg);
        }
    }
    
    pthread_mutex_unlock(&data_mutex);
}

void detect_A9() {
    pthread_mutex_lock(&data_mutex);
    
    // A9检测的简化实现
    // 在真实环境中会使用虚拟地址信息
    // 这里检测异常高频率的目标访问
    uint32_t high_freq_targets[100] = {0};
    uint32_t freq_counts[100] = {0};
    int freq_count = 0;
    
    for (int i = 0; i < packet_count; i++) {
        uint32_t ip = captured_packets[i].source_ip;
        uint32_t target = captured_packets[i].destination_ip; // 简化目标表示
        
        int found = 0;
        for (int j = 0; j < freq_count; j++) {
            if (high_freq_targets[j] == (ip << 8) | (target & 0xFF)) {
                freq_counts[j]++;
                
                if (freq_counts[j] > 100) { // 高频访问阈值
                    char msg[128];
                    uint8_t *sip = (uint8_t*)&ip;
                    uint8_t *dip = (uint8_t*)&target;
                    snprintf(msg, sizeof(msg), 
                            "A9检测: IP %d.%d.%d.%d 可疑内存访问模式",
                            sip[3], sip[2], sip[1], sip[0]);
                    log_message("ALERT", msg);
                    freq_counts[j] = 0; // 重置计数器
                }
                found = 1;
                break;
            }
        }
        
        if (!found && freq_count < 100) {
            high_freq_targets[freq_count] = (ip << 8) | (target & 0xFF);
            freq_counts[freq_count] = 1;
            freq_count++;
        }
    }
    
    pthread_mutex_unlock(&data_mutex);
}


uint32_t ip_to_int(const char *ip) {
    struct in_addr addr;
    inet_aton(ip, &addr);
    return addr.s_addr;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth = (struct ether_header *)packet;
    
    // 仅处理IPv4
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        return;
    }
    
    struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
    
    // 仅处理UDP
    if (ip_hdr->ip_p != IPPROTO_UDP) {
        return;
    }
    
    // 检查RoCEv2端口 (UDP 4791)
    struct udphdr *udp_hdr = (struct udphdr *)(packet + sizeof(struct ether_header) + (ip_hdr->ip_hl << 2));
    if (ntohs(udp_hdr->uh_dport) != 4791) {
        return;
    }
    
    // 解析BTH (Base Transport Header)
    uint8_t *roce_start = (uint8_t *)(udp_hdr + 1);
    
    uint8_t opcode = roce_start[0] & 0x7F; // 提取操作码，清除请求位
    uint32_t dest_qpn = (roce_start[4] << 16) | (roce_start[5] << 8) | roce_start[6];
    uint32_t psn = (roce_start[8] << 16) | (roce_start[9] << 8) | roce_start[10];
    
    // 获取ACK请求标志
    uint8_t ack_req = (roce_start[0] & 0x80) >> 7;
    
    // 锁定数据存储
    pthread_mutex_lock(&data_mutex);
    
    // 存储包信息
    if (packet_count < 1000) {
        PacketInfo *pkt = &captured_packets[packet_count];
        pkt->source_ip = ip_hdr->ip_src.s_addr;
        pkt->destination_ip = ip_hdr->ip_dst.s_addr;
        pkt->qpn = dest_qpn;
        pkt->timestamp = time(NULL);
        pkt->opcode = opcode;
        pkt->psn = psn;
        pkt->ack_req = ack_req;
        packet_count++;
    } else {
        // 缓冲区满，移除旧数据
        memmove(captured_packets, captured_packets + 1, sizeof(PacketInfo) * 999);
        PacketInfo *pkt = &captured_packets[999];
        pkt->source_ip = ip_hdr->ip_src.s_addr;
        pkt->destination_ip = ip_hdr->ip_dst.s_addr;
        pkt->qpn = dest_qpn;
        pkt->timestamp = time(NULL);
        pkt->opcode = opcode;
        pkt->psn = psn;
        pkt->ack_req = ack_req;
    }
    
    // 更新A3状态
    uint32_t source_ip = ip_hdr->ip_src.s_addr;
    int found = 0;
    for (int i = 0; i < a3_state_count; i++) {
        if (a3_states[i].ip == source_ip) {
            a3_states[i].count++;
            found = 1;
            break;
        }
    }
    
    if (!found && a3_state_count < 100) {
        a3_states[a3_state_count].ip = source_ip;
        a3_states[a3_state_count].count = 1;
        a3_states[a3_state_count].cycles = 0;
        a3_state_count++;
    }
    
    pthread_mutex_unlock(&data_mutex);
}

void *detection_thread(void *arg) {
    log_message("INFO", "启动RDMA攻击检测系统");
    
    time_t last_mapping_update = 0;
    int iteration = 0;
    int prev_qp = get_current_qp_count();
    
    while (1) {
        iteration++;
        
        // 定期更新QP映射
        if (time(NULL) - last_mapping_update > 60) {
            update_qp_mappings();
            last_mapping_update = time(NULL);
        }
        
        // 获取当前QP数量
        int current_qp = get_current_qp_count();
        
        // 读取硬件计数器
        CounterMetrics current_metrics = {
            .cm_rx_req = read_hw_counter("/sys/class/infiniband/mlx5_0/ports/1/counters/port_rcv_relaxed_data"),
            .cm_tx_rtu = read_hw_counter("/sys/class/infiniband/mlx5_0/ports/1/counters/port_xmit_data"),
            .rx_read_req = read_hw_counter("/sys/class/infiniband/mlx5_0/ports/1/counters/rx_read_requests"),
            .rx_write_req = read_hw_counter("/sys/class/infiniband/mlx5_0/ports/1/counters/rx_write_requests"),
            .out_of_seq = read_hw_counter("/sys/class/infiniband/mlx5_0/ports/1/counters/out_of_sequence"),
            .dup_req = read_hw_counter("/sys/class/infiniband/mlx5_0/ports/1/counters/duplicate_request")
        };
        
        // 执行检测
        detect_A1(current_metrics);
        detect_A2(current_qp, prev_qp);
        detect_A3();
        detect_A456();
        
        if (iteration % 5 == 0) {
            detect_A7();
        }
        
        if (iteration % 10 == 0) {
            detect_A9();
        }
        
        detect_A8();
        
        // 每5分钟报告状态
        if (time(NULL) - last_notification > 300) {
            char status_msg[256];
            snprintf(status_msg, sizeof(status_msg), 
                    "系统状态: QP数=%d | 包缓冲区=%d | 跟踪IP=%d | 计数器[req=%lu, rtu=%lu, ooseq=%lu]",
                    current_qp, packet_count, a3_state_count, 
                    current_metrics.cm_rx_req, current_metrics.cm_tx_rtu, current_metrics.out_of_seq);
            log_message("STATUS", status_msg);
            last_notification = time(NULL);
        }
        
        // 更新状态
        prev_qp = current_qp;
        prev_metrics = current_metrics;
        
        usleep(500000); // 0.5秒间隔
    }
    
    return NULL;
}

// ==========================
// 流量捕获线程
// ==========================
void *capture_thread(void *arg) {
    char *device = "mlx5_0"; // 使用MLX5设备
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    
    if (!handle) {
        log_message("ERROR", "无法打开网络设备");
        return NULL;
    }
    
    // 设置BPF过滤器
    struct bpf_program filter;
    if (pcap_compile(handle, &filter, "udp port 4791", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        log_message("ERROR", "无法编译过滤器");
        pcap_close(handle);
        return NULL;
    }
    
    if (pcap_setfilter(handle, &filter) == -1) {
        log_message("ERROR", "无法设置过滤器");
        pcap_close(handle);
        return NULL;
    }
    
    log_message("INFO", "开始捕获RoCEv2流量...");
    pcap_loop(handle, -1, packet_handler, NULL);
    
    pcap_close(handle);
    return NULL;
}

int main() {
    // 检查root权限
    if (geteuid() != 0) {
        log_message("WARN", "建议使用root权限运行以获得完整功能");
    }
    
    // 初始化计数器映射
    update_qp_mappings();
    
    // 创建捕获线程
    pthread_t cap_thread;
    if (pthread_create(&cap_thread, NULL, capture_thread, NULL) != 0) {
        perror("创建捕获线程失败");
        return 1;
    }
    
    // 创建检测线程
    pthread_t det_thread;
    if (pthread_create(&det_thread, NULL, detection_thread, NULL) != 0) {
        perror("创建检测线程失败");
        return 1;
    }
    
    // 等待线程结束
    pthread_join(cap_thread, NULL);
    pthread_join(det_thread, NULL);
    
    return 0;
}