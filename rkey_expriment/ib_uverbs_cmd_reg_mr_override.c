#include <stdio.h>
#include <stdlib.h>
#include <infiniband/verbs.h>

int main() {
    struct ibv_device **dev_list;
    struct ibv_device *device;
    struct ibv_context *context;
    struct ibv_pd *pd;
    struct ibv_mr *mr;
    int num_devices;
    int size = 1024;
    char *buf;

    /* 获取 IB 设备列表 */
    dev_list = ibv_get_device_list(&num_devices);
    if (!dev_list) {
        perror("无法获取 IB 设备列表");
        exit(EXIT_FAILURE);
    }
    if (num_devices == 0) {
        fprintf(stderr, "没有找到 IB 设备\n");
        exit(EXIT_FAILURE);
    }

    /* 选择第一个设备并打开 */
    device = dev_list[0];
    context = ibv_open_device(device);
    if (!context) {
        perror("无法打开设备");
        exit(EXIT_FAILURE);
    }

    /* 分配保护域 */
    pd = ibv_alloc_pd(context);
    if (!pd) {
        perror("无法分配保护域");
        exit(EXIT_FAILURE);
    }

    /* 分配内存 */
    buf = malloc(size);
    if (!buf) {
        perror("无法分配内存");
        exit(EXIT_FAILURE);
    }

    /* 注册内存区域，允许本地写、远程读写访问 */
    mr = ibv_reg_mr(pd, buf, size, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
    if (!mr) {
        perror("无法注册内存区域 (MR)");
        exit(EXIT_FAILURE);
    }

    /* 打印 MR 中返回的参数 */
    printf("MR 注册成功:\n");
    printf("  addr   : %p\n", mr->addr);
    printf("  length : %zu\n", mr->length);
    printf("  lkey   : 0x%x\n", mr->lkey);
    printf("  rkey   : 0x%x\n", mr->rkey);

    /* 清理资源 */
    free(buf);
    ibv_dereg_mr(mr);
    ibv_dealloc_pd(pd);
    ibv_close_device(context);
    ibv_free_device_list(dev_list);

    return 0;
}

