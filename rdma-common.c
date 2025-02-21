#include "rdma-common.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <infiniband/verbs.h>
static enum mode s_mode = M_WRITE;
void die(const char *reason)
{
    perror(reason);
    exit(1);
}

// 创建上下文，为每个连接创建独立的CQ和PD
void build_context(struct rdma_cm_id *id)
{
    struct context *new_ctx = (struct context *)malloc(sizeof(struct context));
    if (!new_ctx) {
        die("Failed to allocate memory for context");
    }

    new_ctx->ctx = id->verbs; // 使用连接的设备上下文
    TEST_Z(new_ctx->pd = ibv_alloc_pd(new_ctx->ctx)); // 为每个连接分配独立的保护域
    TEST_Z(new_ctx->comp_channel = ibv_create_comp_channel(new_ctx->ctx)); // 创建独立的完成通道
    TEST_Z(new_ctx->cq = ibv_create_cq(new_ctx->ctx, 10, NULL, new_ctx->comp_channel, 0)); // 创建独立的完成队列
    TEST_NZ(ibv_req_notify_cq(new_ctx->cq, 0));

    id->context = new_ctx; // 将新的上下文关联到rdma_cm_id
}

// 为每个连接创建独立的队列对（QP）并初始化
void build_connection(struct rdma_cm_id *id)
{
    struct connection *conn;
    struct ibv_qp_init_attr qp_attr;

    // 为每个连接创建独立的上下文和队列对
    build_context(id);
    build_qp_attr(&qp_attr, id);  // 使用连接特定的CQ来初始化QP
    struct context *ctx = (struct context *)id->context;
    TEST_NZ(rdma_create_qp(id, ctx->pd, &qp_attr)); // 创建QP
    printf("New QPN: %d\n", id->qp->qp_num);

    id->context = conn = (struct connection *)malloc(sizeof(struct connection));
    conn->id = id;
    conn->qp = id->qp;

    conn->send_state = SS_INIT;
    conn->recv_state = RS_INIT;
    conn->connected = 0;

    register_memory(conn);
    post_receives(conn);
}

// 设置队列对属性，确保每个连接的QP使用独立的CQ
void build_qp_attr(struct ibv_qp_init_attr *qp_attr, struct rdma_cm_id *id)
{
    memset(qp_attr, 0, sizeof(*qp_attr));

    struct context *ctx = (struct context *)id->context;
    qp_attr->send_cq = ctx->cq;  // 使用连接特定的CQ
    qp_attr->recv_cq = ctx->cq;
    qp_attr->qp_type = IBV_QPT_RC;

    qp_attr->cap.max_send_wr = 10;
    qp_attr->cap.max_recv_wr = 10;
    qp_attr->cap.max_send_sge = 1;
    qp_attr->cap.max_recv_sge = 1;
}

// 注册内存区域，用于RDMA传输
void register_memory(struct connection *conn)
{
    conn->send_msg = malloc(sizeof(struct message));
    conn->recv_msg = malloc(sizeof(struct message));

    conn->rdma_local_region = malloc(RDMA_BUFFER_SIZE);
    conn->rdma_remote_region = malloc(RDMA_BUFFER_SIZE);
    struct context *ctx = (struct context *)conn->id->context;
    TEST_Z(conn->send_mr = ibv_reg_mr(
        ctx->pd,
        conn->send_msg,
        sizeof(struct message),
        IBV_ACCESS_LOCAL_WRITE));

    TEST_Z(conn->recv_mr = ibv_reg_mr(
        ctx->pd,
        conn->recv_msg,
        sizeof(struct message),
        IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ));

    TEST_Z(conn->rdma_local_mr = ibv_reg_mr(
        ctx->pd,
        conn->rdma_local_region,
        RDMA_BUFFER_SIZE,
        IBV_ACCESS_LOCAL_WRITE));

    TEST_Z(conn->rdma_remote_mr = ibv_reg_mr(
        ctx->pd,
        conn->rdma_remote_region,
        RDMA_BUFFER_SIZE,
        IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ));
}

// 发送消息的操作
void send_mr(void *context)
{
    struct connection *conn = (struct connection *)context;
    conn->send_msg->type = MSG_MR;
    memcpy(&conn->send_msg->data.mr, conn->rdma_remote_mr, sizeof(struct ibv_mr));

    send_message(conn);
}

// 用于发布接收操作
void post_receives(struct connection *conn)
{
    struct ibv_recv_wr wr, *bad_wr = NULL;
    struct ibv_sge sge;

    wr.wr_id = (uintptr_t)conn;
    wr.next = NULL;
    wr.sg_list = &sge;
    wr.num_sge = 1;

    sge.addr = (uintptr_t)conn->recv_msg;
    sge.length = sizeof(struct message);
    sge.lkey = conn->recv_mr->lkey;

    TEST_NZ(ibv_post_recv(conn->qp, &wr, &bad_wr));
}

// 销毁连接
void destroy_connection(void *context)
{
    struct connection *conn = (struct connection *)context;

    rdma_destroy_qp(conn->id);
    ibv_dereg_mr(conn->send_mr);
    ibv_dereg_mr(conn->recv_mr);
    ibv_dereg_mr(conn->rdma_local_mr);
    ibv_dereg_mr(conn->rdma_remote_mr);

    free(conn->send_msg);
    free(conn->recv_msg);
    free(conn->rdma_local_region);
    free(conn->rdma_remote_region);

    rdma_destroy_id(conn->id);
    free(conn);
}

void on_connect(void *context) {
    struct connection *conn = (struct connection *)context;
    conn->connected = 1;
}


// 发送消息的函数，负责通过 RDMA 写操作将消息发送到远程内存区域
void send_message(struct connection *conn)
{
    struct ibv_send_wr wr, *bad_wr = NULL;
    struct ibv_sge sge;

    // 构造发送请求
    memset(&wr, 0, sizeof(wr));
    wr.wr_id = (uintptr_t)conn;
    wr.opcode = IBV_WR_SEND;  // 使用发送操作
    wr.sg_list = &sge;
    wr.num_sge = 1;
    wr.send_flags = IBV_SEND_SIGNALED;  // 设置发送标志为 SIGNALED，表示完成时会产生中断

    // 设置散列组元素（SGE）
    sge.addr = (uintptr_t)conn->send_msg;  // 消息的发送缓冲区
    sge.length = sizeof(struct message);   // 消息的大小
    sge.lkey = conn->send_mr->lkey;        // 使用连接的 send_mr 键

    // 提交发送请求
    TEST_NZ(ibv_post_send(conn->qp, &wr, &bad_wr));

    // 输出发送信息
    printf("Message sent: %s\n", (char *)conn->send_msg);
}


// 完成事件处理函数，处理RDMA操作的完成事件
void on_completion(struct ibv_wc *wc)
{
    struct connection *conn = (struct connection *)(uintptr_t)wc->wr_id;

    // 检查完成队列中的操作是否成功
    if (wc->status != IBV_WC_SUCCESS) {
        // 如果操作失败，打印错误信息并退出
        printf("Completion failed: %s\n", ibv_wc_status_str(wc->status));
        die("on_completion: status is not IBV_WC_SUCCESS.");
    }

    // 根据操作类型进行相应的处理
    if (wc->opcode & IBV_WC_RECV) {
        // 如果是接收操作
        conn->recv_state++;  // 更新接收状态

        if (conn->recv_msg->type == MSG_MR) {
            // 如果是接收到的内存注册信息
            memcpy(&conn->rdma_remote_mr, &conn->recv_msg->data.mr, sizeof(conn->rdma_remote_mr));
            post_receives(conn);  // 重新发布接收请求

            if (conn->send_state == SS_INIT) {
                // 如果发送操作还没有开始，发送内存注册信息
                send_mr(conn);
            }
        }
    } else {
        // 如果是发送操作
        conn->send_state++;  // 更新发送状态
        printf("Send completed successfully.\n");
    }

    // 如果发送和接收都完成，则进行连接断开操作
    if (conn->send_state == SS_DONE_SENT && conn->recv_state == RS_DONE_RECV) {
        printf("Remote buffer: %s\n", get_peer_message_region(conn));
        rdma_disconnect(conn->id);  // 断开连接
    }
}


// 根据连接的操作模式返回消息区域
char *get_peer_message_region(struct connection *conn)
{
    if (s_mode == M_WRITE) {
        return conn->rdma_remote_region;  // 如果是写操作，返回远程区域
    } else {
        return conn->rdma_local_region;  // 如果是读操作，返回本地区域
    }
}

void set_mode(enum mode m)
{
  s_mode = m;
}

void build_params(struct rdma_conn_param *params)
{
  memset(params, 0, sizeof(*params));

  params->initiator_depth = params->responder_resources = 1;
  params->rnr_retry_count = 7; /* infinite retry */
}



// 根据连接的操作模式返回本地消息区域
void *get_local_message_region(void *context)
{
    struct connection *conn = (struct connection *)context;
    
    if (s_mode == M_WRITE) {
        return conn->rdma_local_region;  // 如果是写操作，返回本地区域
    } else {
        return conn->rdma_remote_region; // 如果是读操作，返回远程区域
    }
}
