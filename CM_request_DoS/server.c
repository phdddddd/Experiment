#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <rdma/rdma_cma.h>
#include <pthread.h>

#define PORT 4567
#define MAX_CONNECTIONS 100

void *handle_connection(void *arg) {
    struct rdma_cm_id *id = (struct rdma_cm_id *)arg;
    struct ibv_pd *pd = NULL;
    struct ibv_cq *cq = NULL;
    struct ibv_qp_init_attr qp_attr = {};
    struct ibv_mr *mr = NULL;
    char *buffer = NULL;

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

    // 分配一块内存并注册内存区域（MR）
    buffer = malloc(1024);
    if (!buffer) {
        perror("malloc");
        goto cleanup_qp;
    }
    mr = ibv_reg_mr(pd, buffer, 1024, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);
    if (!mr) {
        perror("ibv_reg_mr");
        goto cleanup_buffer;
    }

    printf("Waiting for RDMA write...\n");

    // 等待RDMA Write完成
    struct ibv_wc wc;
    while (ibv_poll_cq(cq, 1, &wc) == 0);
    if (wc.status != IBV_WC_SUCCESS) {
        fprintf(stderr, "RDMA Write failed: %d\n", wc.status);
    } else {
        printf("Received data: %s\n", buffer);
    }

cleanup_buffer:
    if (buffer) {
        ibv_dereg_mr(mr);
        free(buffer);
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
    free(id);
    return NULL;
}

void handle_event(struct rdma_cm_event *event) {
    switch (event->event) {
        case RDMA_CM_EVENT_CONNECT_REQUEST: {
            pthread_t thread;
            if (pthread_create(&thread, NULL, handle_connection, event->id)) {
                perror("pthread_create");
                rdma_reject(event->id, NULL, 0);
            } else {
                pthread_detach(thread);  // 分离线程，使其自动清理
            }
            break;
        }
        case RDMA_CM_EVENT_DISCONNECTED:
            printf("Connection disconnected\n");
            break;
        default:
            break;
    }
    rdma_ack_cm_event(event);
}

int main() {
    struct rdma_event_channel *ec = rdma_create_event_channel();
    if (!ec) {
        perror("rdma_create_event_channel");
        exit(1);
    }

    struct rdma_cm_id *listen_id;
    if (rdma_create_id(ec, &listen_id, NULL, RDMA_PS_TCP)) {
        perror("rdma_create_id");
        exit(1);
    }

    struct sockaddr_in listen_addr;
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(PORT);
    listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (rdma_bind_addr(listen_id, (struct sockaddr *)&listen_addr)) {
        perror("rdma_bind_addr");
        exit(1);
    }

    if (rdma_listen(listen_id, MAX_CONNECTIONS)) {
        perror("rdma_listen");
        exit(1);
    }

    printf("Server listening on port %d\n", PORT);

    while (1) {
        struct rdma_cm_event *event;
        if (rdma_get_cm_event(ec, &event)) {
            perror("rdma_get_cm_event");
            continue;
        }

        handle_event(event);
    }

    return 0;
}