#include "rdma_cm_auth.h"
#include <linux/slab.h>
#include <linux/rwsem.h>
#include <linux/hashtable.h>

#define PUBKEY_HASH_BITS 10

struct pubkey_entry {
    struct in_addr ip_addr;
    char *pubkey;
    size_t pubkey_len;
    struct hlist_node node;
};

static DECLARE_RWSEM(pubkey_lock);
static DEFINE_HASHTABLE(pubkey_hashtable, PUBKEY_HASH_BITS);

static u32 ip_hash(struct in_addr ip_addr)
{
    return jhash_1word(ip_addr.s_addr, 0);
}

int kms_register_pubkey(struct in_addr ip_addr, const char *key_data, size_t key_len)
{
    struct pubkey_entry *entry;
    u32 hash = ip_hash(ip_addr);
    
    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry)
        return -ENOMEM;
    
    entry->pubkey = kmalloc(key_len, GFP_KERNEL);
    if (!entry->pubkey) {
        kfree(entry);
        return -ENOMEM;
    }
    
    memcpy(entry->pubkey, key_data, key_len);
    entry->pubkey_len = key_len;
    entry->ip_addr = ip_addr;
    
    down_write(&pubkey_lock);
    hash_add(pubkey_hashtable, &entry->node, hash);
    up_write(&pubkey_lock);
    
    return 0;
}

void kms_unregister_pubkey(struct in_addr ip_addr)
{
    struct pubkey_entry *entry;
    u32 hash = ip_hash(ip_addr);
    
    down_write(&pubkey_lock);
    hash_for_each_possible(pubkey_hashtable, entry, node, hash) {
        if (entry->ip_addr.s_addr == ip_addr.s_addr) {
            hash_del(&entry->node);
            kfree(entry->pubkey);
            kfree(entry);
            break;
        }
    }
    up_write(&pubkey_lock);
}

bool kms_lookup_pubkey(struct in_addr ip_addr, char *out_key, size_t *out_len)
{
    struct pubkey_entry *entry;
    u32 hash = ip_hash(ip_addr);
    bool found = false;
    
    down_read(&pubkey_lock);
    hash_for_each_possible(pubkey_hashtable, entry, node, hash) {
        if (entry->ip_addr.s_addr == ip_addr.s_addr) {
            if (*out_len >= entry->pubkey_len) {
                memcpy(out_key, entry->pubkey, entry->pubkey_len);
                *out_len = entry->pubkey_len;
                found = true;
            }
            break;
        }
    }
    up_read(&pubkey_lock);
    
    return found;
}