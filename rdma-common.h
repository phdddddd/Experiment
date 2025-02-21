#ifndef RDMA_COMMON_H
#define RDMA_COMMON_H

#include <rdma/rdma_cma.h>
#include <infiniband/verbs.h>
#include <pthread.h>
#define TEST_NZ(x) do { if ( (x)) die("error: " #x " failed (returned non-zero)." ); } while (0)
#define TEST_Z(x)  do { if (!(x)) die("error: " #x " failed (returned zero/null)."); } while (0)
// 定义模式
enum mode {
    M_WRITE,
    M_READ
};

// 定义缓冲区大小
static const int RDMA_BUFFER_SIZE = 1024;

// 消息结构体
struct message {
    enum {
        MSG_MR,
        MSG_DONE
    } type;

    union {
        struct ibv_mr mr;
    } data;
};

// 上下文结构体，包含CQ、PD、Comp Channel等
struct context {
    struct ibv_context *ctx;
    struct ibv_pd *pd;
    struct ibv_cq *cq;
    struct ibv_comp_channel *comp_channel;
    pthread_t cq_poller_thread;
};

// 连接结构体，描述每个连接的状态和资源
struct connection {
    struct rdma_cm_id *id;          // RDMA连接ID
    struct ibv_qp *qp;              // 队列对
    int connected;                  // 连接状态

    struct ibv_mr *recv_mr;         // 接收内存区域
    struct ibv_mr *send_mr;         // 发送内存区域
    struct ibv_mr *rdma_local_mr;   // 本地RDMA内存区域
    struct ibv_mr *rdma_remote_mr;  // 远程RDMA内存区域

    struct message *recv_msg;       // 接收消息
    struct message *send_msg;       // 发送消息

    char *rdma_local_region;        // 本地内存区域
    char *rdma_remote_region;       // 远程内存区域

    enum {
        SS_INIT,
        SS_MR_SENT,
        SS_RDMA_SENT,
        SS_DONE_SENT
    } send_state;

    enum {
        RS_INIT,
        RS_MR_RECV,
        RS_DONE_RECV
    } recv_state;
};

// 函数声明
void die(const char *reason);
void build_connection(struct rdma_cm_id *id);
void build_params(struct rdma_conn_param *params);
void destroy_connection(void *context);
void * get_local_message_region(void *context);

void on_connect(void *context);
void send_mr(void *context);
void set_mode(enum mode m);
void build_context(struct rdma_cm_id *id);
void build_qp_attr(struct ibv_qp_init_attr *qp_attr, struct rdma_cm_id *id);
void register_memory(struct connection *conn);
void post_receives(struct connection *conn);
void send_message(struct connection *conn);
char *get_peer_message_region(struct connection *conn);
void on_completion(struct ibv_wc *wc);
void build_params(struct rdma_conn_param *params);

#endif
