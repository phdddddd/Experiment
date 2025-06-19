#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <json-c/json.h>
#include <pthread.h>
#include <fcntl.h>

#define SERVER_PORT 12345
#define MAX_RULES 1024

// 防火墙规则结构
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t action;  // 0: ALLOW, 1: BLOCK
} firewall_rule_t;

// 全局规则缓存
firewall_rule_t rules_cache[MAX_RULES];
int rule_count = 0;
pthread_mutex_t rule_lock = PTHREAD_MUTEX_INITIALIZER;

// 规则添加回调函数
void add_rule_callback(uint32_t src_ip, uint32_t dst_ip, 
                      uint16_t src_port, uint16_t dst_port, 
                      uint8_t protocol, uint8_t action) {
    pthread_mutex_lock(&rule_lock);
    
    if (rule_count < MAX_RULES) {
        rules_cache[rule_count].src_ip = src_ip;
        rules_cache[rule_count].dst_ip = dst_ip;
        rules_cache[rule_count].src_port = src_port;
        rules_cache[rule_count].dst_port = dst_port;
        rules_cache[rule_count].protocol = protocol;
        rules_cache[rule_count].action = action;
        rule_count++;
    }
    
    pthread_mutex_unlock(&rule_lock);
}

// 从攻击检测系统接收告警
void *alert_listener(void *arg) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(SERVER_PORT),
        .sin_addr.s_addr = INADDR_ANY
    };
    
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    
    printf("Listening for alerts on port %d...\n", SERVER_PORT);
    
    while (1) {
        char buffer[1024];
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        
        ssize_t len = recvfrom(sockfd, buffer, sizeof(buffer), 0, 
                              (struct sockaddr *)&client_addr, &addr_len);
        if (len < 0) {
            perror("recvfrom");
            continue;
        }
        
        // 解析JSON格式的告警
        json_object *alert = json_tokener_parse(buffer);
        if (!alert) {
            fprintf(stderr, "Failed to parse JSON alert\n");
            continue;
        }
        
        // 提取告警信息
        const char *src_ip_str = json_object_get_string(json_object_object_get(alert, "src_ip"));
        uint32_t src_ip = inet_addr(src_ip_str);
        uint8_t action = json_object_get_int(json_object_object_get(alert, "action"));
        
        printf("Received alert: Block %s\n", src_ip_str);
        
        // 创建规则 - 阻断来自该IP的所有流量
        add_rule_callback(src_ip, 0, 0, 0, 0, action);
        
        json_object_put(alert);
    }
    
    close(sockfd);
    return NULL;
}

// 向网卡发送规则
void send_rules_to_nic() {
    int nic_fd = open("/dev/nfp_firewall", O_WRONLY);
    if (nic_fd < 0) {
        perror("Failed to open NIC device");
        return;
    }
    
    pthread_mutex_lock(&rule_lock);
    
    // 封装规则为二进制格式
    char buffer[sizeof(firewall_rule_t) * (rule_count + 1)];
    firewall_rule_t *header = (firewall_rule_t *)buffer;
    
    // 头信息
    header->src_ip = 0xFFFFFFFF;  // 标记为规则列表开始
    header->dst_ip = rule_count;
    header++;
    
    // 复制规则
    memcpy(header, rules_cache, sizeof(firewall_rule_t) * rule_count);
    
    // 发送规则
    ssize_t bytes_written = write(nic_fd, buffer, sizeof(firewall_rule_t) * (rule_count + 1));
    if (bytes_written < 0) {
        perror("Failed to write rules to NIC");
    } else {
        printf("Sent %d rules to NIC\n", rule_count);
    }
    
    close(nic_fd);
    pthread_mutex_unlock(&rule_lock);
}

// 规则更新线程
void *rule_update_thread(void *arg) {
    while (1) {
        sleep(1);  // 每秒检查一次
        if (rule_count > 0) {
            send_rules_to_nic();
        }
    }
    return NULL;
}

int main() {
    pthread_t alert_thread, update_thread;
    
    // 启动告警监听线程
    if (pthread_create(&alert_thread, NULL, alert_listener, NULL)) {
        perror("Failed to create alert thread");
        return EXIT_FAILURE;
    }
    
    // 启动规则更新线程
    if (pthread_create(&update_thread, NULL, rule_update_thread, NULL)) {
        perror("Failed to create update thread");
        return EXIT_FAILURE;
    }
    
    // 主线程保持运行
    pthread_join(alert_thread, NULL);
    pthread_join(update_thread, NULL);
    
    return 0;
}