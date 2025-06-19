#ifndef RDMA_CM_AUTH_H
#define RDMA_CM_AUTH_H

#include <linux/types.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/crypto.h>

// 认证标签结构
struct auth_tag {
    uint8_t c_sig[256];   // 加密的签名
    uint8_t c_key[256];   // 加密的对称密钥
    uint8_t c_nonce[256]; // 加密的随机数
};

// RSA密钥大小
#define RSA_KEY_SIZE 2048
#define AES_KEY_SIZE 32
#define NONCE_SIZE 16
#define MAX_CACHED_NONCE 50

// CM消息类型
#define CM_ATTR_CONNECT_REQUEST 0x10
#define CM_ATTR_CONNECT_REPLY   0x13

// 重放保护缓存
struct nonce_cache {
    uint8_t nonces[MAX_CACHED_NONCE][NONCE_SIZE];
    int next_index;
    spinlock_t lock;
};

// KMS API
int kms_register_pubkey(struct in_addr ip_addr, const char *key_data, size_t key_len);
void kms_unregister_pubkey(struct in_addr ip_addr);
bool kms_lookup_pubkey(struct in_addr ip_addr, char *out_key, size_t *out_len);

// 认证处理函数
int rdma_cm_auth_outbound(struct sk_buff *skb, struct net_device *dev);
int rdma_cm_auth_inbound(struct sk_buff *skb, struct net_device *dev);

// 工具函数
void generate_random_nonce(uint8_t *nonce);
int calculate_mac(struct crypto_shash *tfm, const void *data, size_t len, uint8_t *mac);

#endif // RDMA_CM_AUTH_H