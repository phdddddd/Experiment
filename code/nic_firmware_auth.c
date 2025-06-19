#include "rdma_cm_auth.h"
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/device.h>

// 网卡固件的认证处理 (使用类似DPDK的API)
void nic_process_cm_packet(struct nfp_net_rx_ring *rx_ring,
                           struct nfp_net_rx_desc *rxd,
                           struct nfp_net_rx_buf *rxbuf)
{
    struct rte_mbuf *mbuf = rxbuf->mbuf;
    struct iphdr *iph = mbuf->userdata;
    uint8_t *data = rte_pktmbuf_mtod(mbuf, uint8_t *);
    
    // 定位MAD头
    struct ib_mad *mad = (struct ib_mad *)(iph + 1 + sizeof(struct udphdr));
    uint8_t attr_id = mad->data[0]; // Attribute ID
    
    // 只处理ConnectRequest/ConnectReply
    if (attr_id != CM_ATTR_CONNECT_REQUEST && attr_id != CM_ATTR_CONNECT_REPLY) {
        return;
    }
    
    // 定位认证标签位置
    uint8_t *tag_pos = mad->data + 87;
    struct auth_tag *tag = (struct auth_tag *)tag_pos;
    
    // 验证标签 (在网卡固件中实现类似的认证过程)
    if (is_outbound_packet(mbuf)) {
        // 出站处理
        uint8_t nonce[NONCE_SIZE];
        derive_aes_key_nic(NULL, NULL); // 实际使用对称密钥推导
        
        // 生成MAC和签名 (在网卡安全环境内)
        nic_crypto_sign_packet(mbuf, iph->daddr, tag);
        
        // 插入标签
        nic_insert_auth_tag(mbuf, tag_pos, tag);
        
        // 更新IP长度和校验和
        nic_update_ip_len_and_checksum(mbuf);
    } else {
        // 入站处理
        if (nic_verify_auth_tag(mbuf, iph->saddr, tag) != 0) {
            // 验证失败，丢弃包
            rte_pktmbuf_free(mbuf);
            return;
        }
        
        // 从报文中移除标签
        nic_remove_auth_tag(mbuf, tag_pos);
        
        // 更新IP头
        nic_update_ip_len_and_checksum(mbuf);
    }
    
    // 继续正常的RDMA处理流程
    nic_process_rdma_packet(rx_ring, rxd, rxbuf);
}

// 网卡上的认证实现 (在安全环境中)
int nic_verify_auth_tag(struct rte_mbuf *mbuf, uint32_t src_ip, struct auth_tag *tag)
{
    uint8_t nonce[NONCE_SIZE];
    uint8_t mac[SHA256_DIGEST_LENGTH];
    uint8_t signature[256];
    
    // 1. 获取对方公钥
    RSA *remote_pub = nic_get_remote_public_key(src_ip);
    
    // 2. 解密对称密钥和随机数 (使用网卡的安全引擎)
    nic_rsa_decrypt(tag->c_key, nonce, sizeof(nonce));
    nic_rsa_decrypt(tag->c_nonce, nonce, sizeof(nonce));
    
    // 3. 防重放检查
    if (nic_is_nonce_replayed(nonce)) {
        return -1;
    }
    nic_add_nonce_to_cache(nonce);
    
    // 4. 解密签名
    nic_aes_decrypt(tag->c_sig, signature, sizeof(signature));
    
    // 5. 重新计算MAC (不包括标签)
    size_t orig_len = /* 计算原始长度 */;
    uint8_t *orig_data = /* 定位原始数据 */;
    nic_calculate_sha256(orig_data, orig_len, mac);
    
    // 6. 验证签名
    if (!nic_rsa_verify_signature(remote_pub, mac, signature)) {
        return -1;
    }
    
    return 0;
}

// 网卡上的认证实现 (在安全环境中)
void nic_sign_packet(struct rte_mbuf *mbuf, uint32_t dst_ip, struct auth_tag *tag)
{
    // 1. 获取私钥和对方公钥
    RSA *local_priv = nic_get_local_private_key();
    RSA *remote_pub = nic_get_remote_public_key(dst_ip);
    
    // 2. 生成随机数
    nic_generate_random_nonce(tag->nonce);
    
    // 3. 计算MAC
    uint8_t mac[SHA256_DIGEST_LENGTH];
    nic_calculate_sha256(mbuf->data, mbuf->data_len, mac);
    
    // 4. 签名MAC
    nic_rsa_sign(local_priv, mac, tag->signature);
    
    // 5. 生成对称密钥
    nic_derive_aes_key(tag->nonce, aes_key);
    
    // 6. 加密签名
    nic_aes_encrypt(tag->signature, tag->c_sig);
    
    // 7. 加密对称密钥和随机数
    nic_rsa_encrypt(remote_pub, aes_key, tag->c_key);
    nic_rsa_encrypt(remote_pub, tag->nonce, tag->c_nonce);
}