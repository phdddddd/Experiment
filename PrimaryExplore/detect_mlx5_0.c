#include <stdio.h>
#include <pcap.h>

int main() {
    pcap_if_t *alldevs, *device;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 查找所有设备
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error finding devices: %s\n", errbuf);
        return 1;
    }

    if (alldevs == NULL) {
        printf("No devices found!\n");
        return 1;
    }

    // 打印设备信息
    printf("Devices found on this machine:\n");
    for (device = alldevs; device; device = device->next) {
        printf("Name: %s\n", device->name); // 设备名称
        printf("Description: %s\n", device->description ? device->description : "No description available");

        // 打印设备的额外信息，如果有的话
        pcap_addr_t *address;
        for (address = device->addresses; address; address = address->next) {
            if (address->addr) {
                char ip[INET6_ADDRSTRLEN];
                if (address->addr->sa_family == AF_INET) {
                    // IPv4 地址
                    struct sockaddr_in *sock_in = (struct sockaddr_in *)address->addr;
                    inet_ntop(AF_INET, &(sock_in->sin_addr), ip, sizeof(ip));
                    printf("IPv4 Address: %s\n", ip);
                } else if (address->addr->sa_family == AF_INET6) {
                    // IPv6 地址
                    struct sockaddr_in6 *sock_in6 = (struct sockaddr_in6 *)address->addr;
                    inet_ntop(AF_INET6, &(sock_in6->sin6_addr), ip, sizeof(ip));
                    printf("IPv6 Address: %s\n", ip);
                }
            }
        }
        printf("\n");
    }

    // 释放资源
    pcap_freealldevs(alldevs);
    return 0;
}
