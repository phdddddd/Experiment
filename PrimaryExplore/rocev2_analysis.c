#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

// 手动定义以太网头部
#define ETHER_ADDR_LEN 6
struct ether_header {
    uint8_t ether_dhost[ETHER_ADDR_LEN]; // 目的 MAC 地址
    uint8_t ether_shost[ETHER_ADDR_LEN]; // 源 MAC 地址
    uint16_t ether_type;                 // 以太网类型
};

// 定义 RoCEv2 特定字段的结构
struct rocev2_bth {
    uint8_t opcode;                     // 操作码
    uint8_t solicited_event;            // Solicited Event
    uint16_t pkey;                      // Partition Key
    uint32_t destination_qp;            // Destination Queue Pair
    uint32_t packet_sequence_number;    // Packet Sequence Number
};

// 数据包处理函数
void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    // 获取以太网头部后的数据
    struct ether_header {
        unsigned char ether_dhost[6]; // 目的 MAC 地址
        unsigned char ether_shost[6]; // 源 MAC 地址
        unsigned short ether_type;   // 以太网类型
    } *eth_header;

    eth_header = (struct ether_header *) packet;

    // 检查是否为 IPv4 数据包
    if (ntohs(eth_header->ether_type) == 0x0800) { // 0x0800 表示 IPv4
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));

        // 打印源 IP 和目的 IP
        printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
    }
}
int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *device = "mlx5_0"; // 指定设备名称

    // 打开设备进行数据包捕获
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", device, errbuf);
        return 1;
    }
 
    // 设置过滤器，只捕获 UDP（RoCEv2 基于 UDP）
    struct bpf_program filter;
    char filter_exp[] = "udp";
    if (pcap_compile(handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    printf("Listening on device %s...\n", device);

    // 开始捕获数据包并调用回调函数
    if (pcap_loop(handle, 0, packet_handler, NULL) < 0) {
        fprintf(stderr, "Error during packet capture: %s\n", pcap_geterr(handle));
        return 1;
    }

    // 释放资源
    pcap_close(handle);
    return 0;
}
