#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <rdma/rdma_cma.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 4567

void perform_rdma_write(struct rdma_cm_id *id, const void *local_buffer, size_t size) {
    struct ibv_pd *pd = NULL;
    struct ibv_cq *cq = NULL;
    struct ibv_qp_init_attr qp_attr = {};
    struct ibv_mr *mr = NULL;
    struct ibv_send_wr wr = {}, *bad_wr;
    struct ibv_sge sge;

    // 初始化保护域（PD）
    pd = ibv_alloc_pd(id->verbs);
    if (!pd) {
        perror("ibv_alloc_pd");
        goto cleanup_pd;
    }

    // 创建完成队列（CQ）
    cq = ibv_create_cq(id->verbs, 10, NULL, NULL, 0);
    if (!cq) {
        perror("ibv_create_cq");
        goto cleanup_pd;
    }

    // 初始化QP属性
    memset(&qp_attr, 0, sizeof(qp_attr));
    qp_attr.cap.max_send_wr = 10;
    qp_attr.cap.max_recv_wr = 10;
    qp_attr.cap.max_send_sge = 1;
    qp_attr.cap.max_recv_sge = 1;
    qp_attr.qp_type = IBV_QPT_RC;
    qp_attr.send_cq = cq;
    qp_attr.recv_cq = cq;

    // 创建QP
    if (rdma_create_qp(id, pd, &qp_attr)) {
        perror("rdma_create_qp");
        goto cleanup_cq;
    }

    // 注册本地内存区域（MR）
    mr = ibv_reg_mr(pd, (void *)local_buffer, size, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);
    if (!mr) {
        perror("ibv_reg_mr");
        goto cleanup_qp;
    }

    // 设置RDMA Write的工作请求（WR）
    sge.addr = (uintptr_t)local_buffer;
    sge.length = size;
    sge.lkey = mr->lkey;

    wr.opcode = IBV_WR_RDMA_WRITE;
    wr.sg_list = &sge;
    wr.num_sge = 1;
    wr.wr.rdma.remote_addr = (uintptr_t)((char *)(id->context));  // 这里需要服务器端提供的远程地址
    wr.wr.rdma.rkey = *(uint32_t *)((char *)(id->context) + sizeof(uintptr_t));  // 这里需要服务器端提供的远程RKey

    // 执行RDMA Write
    if (ibv_post_send(id->qp, &wr, &bad_wr)) {
        perror("ibv_post_send");
        goto cleanup_mr;
    }

    // 等待RDMA Write完成
    struct ibv_wc wc;
    while (ibv_poll_cq(cq, 1, &wc) == 0);
    if (wc.status != IBV_WC_SUCCESS) {
        fprintf(stderr, "RDMA Write failed: %d\n", wc.status);
    } else {
        printf("RDMA Write completed successfully\n");
    }

cleanup_mr:
    if (mr) {
        ibv_dereg_mr(mr);
    }
cleanup_qp:
    if (id->qp) {
        rdma_destroy_qp(id);
    }
cleanup_cq:
    if (cq) {
        ibv_destroy_cq(cq);
    }
cleanup_pd:
    if (pd) {
        ibv_dealloc_pd(pd);
    }
}

int main() {
    struct rdma_event_channel *ec = rdma_create_event_channel();
    if (!ec) {
        perror("rdma_create_event_channel");
        exit(1);
    }

    struct rdma_cm_id *id;
    if (rdma_create_id(ec, &id, NULL, RDMA_PS_TCP)) {
        perror("rdma_create_id");
        exit(1);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, SERVER_IP, &addr.sin_addr);
    addr.sin_port = htons(SERVER_PORT);

    if (rdma_resolve_addr(id, NULL, (struct sockaddr *)&addr, 2000)) {
        perror("rdma_resolve_addr");
        exit(1);
    }

    struct rdma_cm_event *event;
    if (rdma_get_cm_event(ec, &event)) {
        perror("rdma_get_cm_event");
        exit(1);
    }
    if (event->event != RDMA_CM_EVENT_ADDR_RESOLVED) {
        fprintf(stderr, "Address resolution failed: %d\n", event->event);
        exit(1);
    }
    rdma_ack_cm_event(event);

    if (rdma_resolve_route(id, 2000)) {
        perror("rdma_resolve_route");
        exit(1);
    }

    if (rdma_get_cm_event(ec, &event)) {
        perror("rdma_get_cm_event");
        exit(1);
    }
    if (event->event != RDMA_CM_EVENT_ROUTE_RESOLVED) {
        fprintf(stderr, "Route resolution failed: %d\n", event->event);
        exit(1);
    }
    rdma_ack_cm_event(event);

    struct rdma_conn_param param = {};
    if (rdma_connect(id, &param)) {
        perror("rdma_connect");
        exit(1);
    }

    // 等待连接建立完成
    if (rdma_get_cm_event(ec, &event)) {
        perror("rdma_get_cm_event");
        exit(1);
    }
    if (event->event != RDMA_CM_EVENT_ESTABLISHED) {
        fprintf(stderr, "Connection establishment failed: %d\n", event->event);
        exit(1);
    }
    rdma_ack_cm_event(event);

    // 准备要发送的数据
    const char *data = "Hello, RDMA!";
    size_t size = strlen(data) + 1;

    // 将服务器的远程地址和RKey存储在id->context中
    uintptr_t remote_addr = (uintptr_t)id->qp->qp_num;  // 需要服务器提供实际的remote_addr
    uint32_t rkey = id->qp->rkey;  // 需要服务器提供实际的rkey
    id->context = malloc(sizeof(remote_addr) + sizeof(rkey));
    memcpy(id->context, &remote_addr, sizeof(remote_addr));
    memcpy((char *)id->context + sizeof(remote_addr), &rkey, sizeof(rkey));

    // 执行RDMA Write
    perform_rdma_write(id, data, size);

    rdma_disconnect(id);
    rdma_destroy_id(id);
    rdma_destroy_event_channel(ec);

    return 0;
}