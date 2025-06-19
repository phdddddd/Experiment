#include "rdma_cm_auth.h"
#include <linux/crypto.h>
#include <linux/random.h>
#include <linux/netdevice.h>
#include <net/ip.h>
#include <net/rdma_cm.h>
#include <crypto/akcipher.h>
#include <crypto/skcipher.h>

// 全局重放保护缓存
static struct nonce_cache global_nonce_cache;

// 初始化模块
int __init auth_module_init(void)
{
    spin_lock_init(&global_nonce_cache.lock);
    global_nonce_cache.next_index = 0;
    memset(global_nonce_cache.nonces, 0, sizeof(global_nonce_cache.nonces));
    
    // 在这里初始化crypto框架需要的各种tfm
    return 0;
}

// 生成随机nonce
void generate_random_nonce(uint8_t *nonce)
{
    get_random_bytes(nonce, NONCE_SIZE);
}

// 计算消息MAC
int calculate_mac(struct crypto_shash *tfm, const void *data, size_t len, uint8_t *mac)
{
    SHASH_DESC_ON_STACK(desc, tfm);
    int err;
    
    desc->tfm = tfm;
    
    err = crypto_shash_digest(desc, data, len, mac);
    if (err)
        return err;
        
    return 0;
}

// 处理出站CM报文 (ConnectRequest/ConnectReply)
int rdma_cm_auth_outbound(struct sk_buff *skb, struct net_device *dev)
{
    struct iphdr *iph = ip_hdr(skb);
    struct rdma_cm_hdr *cmh;
    uint8_t nonce[NONCE_SIZE];
    uint8_t mac[SHA256_DIGEST_LENGTH];
    struct crypto_akcipher *rsa_tfm;
    struct crypto_shash *sha_tfm;
    struct crypto_skcipher *aes_tfm;
    uint8_t *msg_start;
    uint8_t *tag_pos;
    uint8_t tag_buffer[sizeof(struct auth_tag)];
    struct auth_tag *tag = (struct auth_tag *)tag_buffer;
    int err;
    
    // 1. 获取私钥和对方公钥 
    RSA *local_priv = get_local_private_key();
    RSA *remote_pub = get_remote_public_key(iph->daddr);
    
    // 2. 生成随机数
    generate_random_nonce(nonce);
    
    // 3. 计算整个消息的MAC
    sha_tfm = crypto_alloc_shash("sha256", 0, 0);
    msg_start = skb_mac_header(skb) + (iph->ihl * 4);
    
    err = calculate_mac(sha_tfm, msg_start, skb->len - (iph->ihl * 4), mac);
    if (err)
        return err;
    
    // 4. 用私钥对MAC签名
    uint8_t signature[256];
    size_t sig_len = sizeof(signature);
    
    sign_mac(local_priv, mac, sizeof(mac), signature, &sig_len);
    
    // 5. 生成对称密钥
    uint8_t aes_key[AES_KEY_SIZE] = {0};
    derive_aes_key(nonce, aes_key);
    
    // 6. 加密签名
    aes_tfm = crypto_alloc_skcipher("aes", 0, 0);
    struct skcipher_request *req = skcipher_request_alloc(aes_tfm, GFP_KERNEL);
    struct scatterlist src_sg, dst_sg;
    
    sg_init_one(&src_sg, signature, sig_len);
    sg_init_one(&dst_sg, tag->c_sig, sizeof(tag->c_sig));
    
    skcipher_request_set_callback(req, 0, NULL, NULL);
    skcipher_request_set_crypt(req, &src_sg, &dst_sg, sig_len, NULL);
    
    crypto_skcipher_encrypt(req);
    skcipher_request_free(req);
    
    // 7. 加密对称密钥和随机数
    rsa_tfm = crypto_alloc_akcipher("rsa", 0, 0);
    

    encrypt_with_rsa(remote_pub, aes_key, sizeof(aes_key), tag->c_key);
    encrypt_with_rsa(remote_pub, nonce, sizeof(nonce), tag->c_nonce);
    
    // 8. 将标签插入报文
    tag_pos = msg_start + 87; // MAD payload + offset
    if (skb_tailroom(skb) < sizeof(struct auth_tag)) {
        struct sk_buff *new_skb = skb_copy_expand(skb, 0, sizeof(struct auth_tag), GFP_ATOMIC);
        if (!new_skb) {
            return -ENOMEM;
        }
        kfree_skb(skb);
        skb = new_skb;
        iph = ip_hdr(skb);
        msg_start = skb_mac_header(skb) + (iph->ihl * 4);
        tag_pos = msg_start + 87;
    }
    
    memcpy(tag_pos, tag, sizeof(struct auth_tag));
    
    // 更新IP长度和校验和
    iph->tot_len = htons(ntohs(iph->tot_len) + sizeof(struct auth_tag));
    iph->check = 0;
    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
    
    // 清理
    crypto_free_akcipher(rsa_tfm);
    crypto_free_shash(sha_tfm);
    crypto_free_skcipher(aes_tfm);
    
    return 0;
}

// 处理入站CM报文 (ConnectRequest/ConnectReply)
int rdma_cm_auth_inbound(struct sk_buff *skb, struct net_device *dev)
{
    struct iphdr *iph = ip_hdr(skb);
    struct rdma_cm_hdr *cmh;
    uint8_t nonce[NONCE_SIZE];
    uint8_t mac[SHA256_DIGEST_LENGTH];
    struct crypto_akcipher *rsa_tfm;
    struct crypto_shash *sha_tfm;
    struct crypto_skcipher *aes_tfm;
    uint8_t *msg_start;
    uint8_t *tag_pos;
    struct auth_tag *tag;
    int err;
    
    // 1. 定位标签位置
    msg_start = skb_mac_header(skb) + (iph->ihl * 4);
    tag_pos = msg_start + 87;
    tag = (struct auth_tag *)tag_pos;
    
    // 2. 获取私钥和对方公钥
    RSA *local_priv = get_local_private_key();
    RSA *remote_pub = get_remote_public_key(iph->saddr);
    
    // 3. 解密随机数和对称密钥
    rsa_tfm = crypto_alloc_akcipher("rsa", 0, 0);
    
    decrypt_with_rsa(local_priv, tag->c_key, nonce, sizeof(nonce));
    decrypt_with_rsa(local_priv, tag->c_nonce, nonce, sizeof(nonce));
    
    // 4. 防重放检查
    if (is_nonce_replayed(&global_nonce_cache, nonce)) {
        // 记录日志并丢弃
        return -EINVAL;
    }
    add_nonce_to_cache(&global_nonce_cache, nonce);
    
    // 5. 解密签名
    uint8_t decrypted_signature[256];
    size_t sig_len = sizeof(decrypted_signature);
    
    aes_tfm = crypto_alloc_skcipher("aes", 0, 0);
    struct skcipher_request *req = skcipher_request_alloc(aes_tfm, GFP_KERNEL);
    struct scatterlist src_sg, dst_sg;
    
    sg_init_one(&src_sg, tag->c_sig, sizeof(tag->c_sig));
    sg_init_one(&dst_sg, decrypted_signature, sig_len);
    
    skcipher_request_set_callback(req, 0, NULL, NULL);
    skcipher_request_set_crypt(req, &src_sg, &dst_sg, sig_len, NULL);
    
    crypto_skcipher_decrypt(req);
    skcipher_request_free(req);
    
    // 6. 验证签名
    // 重新计算MAC 
    sha_tfm = crypto_alloc_shash("sha256", 0, 0);
    
    uint8_t orig_mac[SHA256_DIGEST_LENGTH];
    size_t orig_len = tag_pos - msg_start;
    err = calculate_mac(sha_tfm, msg_start, orig_len, orig_mac);
    if (err)
        return err;
    
    // 验证签名 
    if (!verify_signature(remote_pub, orig_mac, sizeof(orig_mac), decrypted_signature)) {
        return -EINVAL;
    }
    
    // 7. 从报文中移除标签
    memmove(tag_pos, tag_pos + sizeof(struct auth_tag), 
            skb_tail_pointer(skb) - (tag_pos + sizeof(struct auth_tag)));
    skb_trim(skb, skb->len - sizeof(struct auth_tag));
    
    // 更新IP头
    iph = ip_hdr(skb);
    iph->tot_len = htons(ntohs(iph->tot_len) - sizeof(struct auth_tag));
    iph->check = 0;
    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
    
    // 清理
    crypto_free_akcipher(rsa_tfm);
    crypto_free_shash(sha_tfm);
    crypto_free_skcipher(aes_tfm);
    
    return 0;
}

// 重放保护相关函数
static bool is_nonce_replayed(struct nonce_cache *cache, const uint8_t *nonce)
{
    unsigned long flags;
    bool replayed = false;
    int i;
    
    spin_lock_irqsave(&cache->lock, flags);
    
    for (i = 0; i < MAX_CACHED_NONCE; i++) {
        if (memcmp(cache->nonces[i], nonce, NONCE_SIZE) == 0) {
            replayed = true;
            break;
        }
    }
    
    spin_unlock_irqrestore(&cache->lock, flags);
    return replayed;
}

static void add_nonce_to_cache(struct nonce_cache *cache, const uint8_t *nonce)
{
    unsigned long flags;
    
    spin_lock_irqsave(&cache->lock, flags);
    
    memcpy(cache->nonces[cache->next_index], nonce, NONCE_SIZE);
    cache->next_index = (cache->next_index + 1) % MAX_CACHED_NONCE;
    
    spin_unlock_irqrestore(&cache->lock, flags);
}