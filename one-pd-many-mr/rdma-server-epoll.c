#include "rdma-common.h"
#include <pthread.h>
#include <sys/queue.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <fcntl.h>

#define MAX_THREADS 50
#define MAX_EVENTS 50

void *worker_thread(void *arg);
void submit_task(void (*func)(void *), void *arg);
void process_connection(void *arg);
void on_event_wrapper(void *arg);
void usage(const char *argv0);
pthread_mutex_t task_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t task_queue_cond = PTHREAD_COND_INITIALIZER;
TAILQ_HEAD(task_queue, task) task_queue;

struct task {
    void (*func)(void *arg);
    void *arg;
    TAILQ_ENTRY(task) entries;
};

int main(int argc, char **argv) {
    struct sockaddr_in addr;
    struct rdma_cm_event *event = NULL;
    struct rdma_cm_id *listener = NULL;
    struct rdma_event_channel *ec = NULL;
    int epoll_fd, nfds;
    struct epoll_event ev, events[MAX_EVENTS];
    uint16_t port = 6666;

    // 解析命令行参数
    if (argc != 2)
        usage(argv[0]);

    if (strcmp(argv[1], "write") == 0)
        set_mode(M_WRITE);
    else if (strcmp(argv[1], "read") == 0)
        set_mode(M_READ);
    else
        usage(argv[0]);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    // 创建事件通道
    TEST_Z(ec = rdma_create_event_channel());
    TEST_NZ(rdma_create_id(ec, &listener, NULL, RDMA_PS_TCP));
    TEST_NZ(rdma_bind_addr(listener, (struct sockaddr *)&addr));
    TEST_NZ(rdma_listen(listener, 100));

    // 创建 epoll 实例
    epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("epoll_create1");
        exit(EXIT_FAILURE);
    }

    // 将事件通道的文件描述符添加到 epoll 中
    ev.events = EPOLLIN;
    ev.data.ptr = listener;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ec->fd, &ev) == -1) {
        perror("epoll_ctl: listener");
        exit(EXIT_FAILURE);
    }

    // 初始化任务队列和线程池
    TAILQ_INIT(&task_queue);
    for (int i = 0; i < MAX_THREADS; ++i) {
        pthread_t thread;
        pthread_create(&thread, NULL, worker_thread, NULL);
    }

    printf("Listening on port %d.\n", port);

    while (1) {
        nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);  // 等待 epoll 事件
        if (nfds == -1) {
            perror("epoll_wait");
            exit(EXIT_FAILURE);
        }

        for (int n = 0; n < nfds; ++n) {
            if (events[n].events & EPOLLIN) {
                if (events[n].data.ptr == listener) {
                    // 接受连接请求
                    TEST_NZ(rdma_get_cm_event(ec, &event));
                    struct rdma_cm_event *event_copy = malloc(sizeof(struct rdma_cm_event));
                    memcpy(event_copy, event, sizeof(struct rdma_cm_event));
                    rdma_ack_cm_event(event);
                    submit_task(on_event_wrapper, event_copy);  // 将事件处理任务添加到任务队列
                } else {
                    // 处理现有连接的事件
                    struct rdma_cm_id *id = (struct rdma_cm_id *)events[n].data.ptr;
                    submit_task(process_connection, id->context);  // 将数据处理任务添加到队列
                }
            }
        }
    }

    rdma_destroy_id(listener);
    rdma_destroy_event_channel(ec);
    close(epoll_fd);
    return 0;
}

// 线程池工作函数，处理任务队列中的任务
void *worker_thread(void *arg) {
    while (1) {
        struct task *t;
        pthread_mutex_lock(&task_queue_mutex);
        while (TAILQ_EMPTY(&task_queue)) {
            pthread_cond_wait(&task_queue_cond, &task_queue_mutex);
        }
        t = TAILQ_FIRST(&task_queue);
        TAILQ_REMOVE(&task_queue, t, entries);
        pthread_mutex_unlock(&task_queue_mutex);

        t->func(t->arg);  // 执行任务
        free(t);
    }
    return NULL;
}

// 提交任务到队列
void submit_task(void (*func)(void *), void *arg) {
    struct task *t = malloc(sizeof(struct task));
    t->func = func;
    t->arg = arg;

    pthread_mutex_lock(&task_queue_mutex);
    TAILQ_INSERT_TAIL(&task_queue, t, entries);
    pthread_cond_signal(&task_queue_cond);  // 通知一个工作线程
    pthread_mutex_unlock(&task_queue_mutex);
}

// 处理连接的完成事件
void process_connection(void *arg) {
    struct connection *conn = (struct connection *)arg;
    struct ibv_wc wc;
    int rc = ibv_poll_cq(conn->qp->send_cq, 1, &wc);  // 检查发送完成队列
    if (rc > 0) {
        on_completion(&wc);  // 处理完成事件
    }
}



// 用于处理连接请求的函数
int on_connect_request(struct rdma_cm_id *id) {
    struct rdma_conn_param cm_params;
    printf("Received connection request.\n");

    build_connection(id);  // 为每个连接创建独立的上下文和QP
    build_params(&cm_params);
    sprintf(get_local_message_region(id->context), "Message from passive/server side with pid %d", getpid());
    TEST_NZ(rdma_accept(id, &cm_params));

    return 0;
}

// 处理连接成功的事件
int on_connection(struct rdma_cm_id *id) {
    on_connect(id->context);
    return 0;
}

// 处理连接断开的事件
int on_disconnect(struct rdma_cm_id *id) {
    printf("Peer disconnected.\n");
    destroy_connection(id->context);  // 销毁连接
    return 0;
}

// 事件处理的主逻辑，处理连接请求、建立和断开
int on_event(struct rdma_cm_event *event) {
    int r = 0;

    if (event->event == RDMA_CM_EVENT_CONNECT_REQUEST)
        r = on_connect_request(event->id);
    else if (event->event == RDMA_CM_EVENT_ESTABLISHED)
        r = on_connection(event->id);
    else if (event->event == RDMA_CM_EVENT_DISCONNECTED)
        r = on_disconnect(event->id);
    else
        die("on_event: unknown event.");

    return r;
}
void on_event_wrapper(void *arg) {
    struct rdma_cm_event *event = (struct rdma_cm_event *)arg;
    on_event(event);  // 调用原始的 on_event 函数
}
// 打印用法信息
void usage(const char *argv0) {
    fprintf(stderr, "usage: %s <mode>\n  mode = \"read\", \"write\"\n", argv0);
    exit(1);
}
