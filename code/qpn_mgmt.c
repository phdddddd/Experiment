#include <linux/module.h>
#include <linux/bpf.h>
#include <linux/time.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("RDMA Security");
MODULE_DESCRIPTION("QPN Mapping Management System");

#define MAPPING_TIMEOUT 60 /* 60 seconds */

struct qpn_mapping_entry {
    u32 local_ip;
    u32 remote_ip;
    u32 local_qpn;
    u32 remote_qpn;
    unsigned long last_active;
    struct list_head list;
};

static LIST_HEAD(active_mappings);
static DEFINE_SPINLOCK(mapping_lock);
static struct timer_list mapping_timer;
void add_mapping_entry(u32 local_ip, u32 remote_ip, u32 local_qpn, u32 remote_qpn)
{
    struct qpn_mapping_entry *new;
    unsigned long flags;
    
    new = kmalloc(sizeof(*new), GFP_KERNEL);
    if (!new) return;
    
    new->local_ip = local_ip;
    new->remote_ip = remote_ip;
    new->local_qpn = local_qpn;
    new->remote_qpn = remote_qpn;
    new->last_active = jiffies;
    
    spin_lock_irqsave(&mapping_lock, flags);
    list_add_tail(&new->list, &active_mappings);
    spin_unlock_irqrestore(&mapping_lock, flags);
}

struct qpn_mapping_entry *find_mapping(u32 local_ip, u32 remote_ip, u32 local_qpn)
{
    struct qpn_mapping_entry *entry;
    unsigned long flags;
    struct qpn_mapping_entry *found = NULL;
    
    spin_lock_irqsave(&mapping_lock, flags);
    
    list_for_each_entry(entry, &active_mappings, list) {
        if (entry->local_ip == local_ip &&
            entry->remote_ip == remote_ip &&
            entry->local_qpn == local_qpn) {
            found = entry;
            found->last_active = jiffies;
            break;
        }
    }
    
    spin_unlock_irqrestore(&mapping_lock, flags);
    return found;
}
void purge_expired_mappings(struct timer_list *timer)
{
    struct qpn_mapping_entry *entry, *tmp;
    unsigned long flags;
    unsigned long timeout = msecs_to_jiffies(MAPPING_TIMEOUT * 1000);
    
    spin_lock_irqsave(&mapping_lock, flags);
    
    list_for_each_entry_safe(entry, tmp, &active_mappings, list) {
        if (time_after(jiffies, entry->last_active + timeout)) {
            list_del(&entry->list);
            kfree(entry);
        }
    }
    
    spin_unlock_irqrestore(&mapping_lock, flags);
    
    mod_timer(&mapping_timer, jiffies + msecs_to_jiffies(1000));
}

void rdma_cm_connection_handler(struct rdma_cm_event *event)
{
    if (event->event != RDMA_CM_EVENT_ESTABLISHED)
        return;
    
    struct rdma_conn_param *conn_param = &event->param.conn;
    struct rdma_cm_id *id = event->id;
    
    u32 local_qpn = id->qp->qp_num;
    u32 remote_qpn = conn_param->responder_resources;
    u32 remote_ip = ntohl(id->route.addr.dst_addr.sin_addr.s_addr);
    
    add_mapping_entry(0, remote_ip, local_qpn, remote_qpn);
}

void rdma_cm_disconnect_handler(struct rdma_cm_id *id)
{
    struct qpn_mapping_entry *entry;
    unsigned long flags;
    u32 local_qpn = id->qp->qp_num;
    u32 remote_ip = ntohl(id->route.addr.dst_addr.sin_addr.s_addr);
    
    spin_lock_irqsave(&mapping_lock, flags);
    
    list_for_each_entry(entry, &active_mappings, list) {
        if (entry->local_qpn == local_qpn && 
            entry->remote_ip == remote_ip) {
            list_del(&entry->list);
            kfree(entry);
            break;
        }
    }
    
    spin_unlock_irqrestore(&mapping_lock, flags);
}

static int __init qpn_mgmt_init(void)
{
    timer_setup(&mapping_timer, purge_expired_mappings, 0);
    mod_timer(&mapping_timer, jiffies + msecs_to_jiffies(1000));
    
    // 注册RDMA CM事件处理器
    rdma_cm_set_event_handler(rdma_cm_connection_handler);
    
    printk(KERN_INFO "QPN Mapping Management Module Loaded\n");
    return 0;
}


static void __exit qpn_mgmt_exit(void)
{
    del_timer(&mapping_timer);

    struct qpn_mapping_entry *entry, *tmp;
    list_for_each_entry_safe(entry, tmp, &active_mappings, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    
    printk(KERN_INFO "QPN Mapping Management Module Unloaded\n");
}

module_init(qpn_mgmt_init);
module_exit(qpn_mgmt_exit);