#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <infiniband/verbs.h>
#include <string.h>

#define NUM_MR 100000    // MR 数量
#define MR_SIZE 64      // 每个 MR 的内存大小

// 用于存放相邻差值及计数的结构体
typedef struct {
    uint32_t diff;
    int count;
} diff_count_t;

// 16位左循环移位函数
uint16_t rol(uint16_t x, int shift) {
    return ((x << shift) | (x >> (16 - shift))) & 0xFFFF;
}

// 轮函数：F(x, k) = ROL(x, 3) + k (模 2^16)
uint16_t F(uint16_t x, uint16_t k) {
    return (rol(x, 3) + k) & 0xFFFF;
}

// 修改后的 Feistel 加密函数：在返回结果前交换左右半部
uint32_t feistel_encrypt(uint32_t block, uint16_t keys[4]) {
    uint16_t L = (block >> 16) & 0xFFFF;
    uint16_t R = block & 0xFFFF;
    for (int i = 0; i < 4; i++) {
        uint16_t temp = L ^ F(R, keys[i]);
        L = R;
        R = temp;
    }
    // 关键：输出前交换左右半部，使密文为 (R, L)
    return ((uint32_t)R << 16) | L;
}

// 解密函数：只需要反转密钥顺序后调用加密函数
uint32_t feistel_decrypt(uint32_t block, uint16_t keys[4]) {
    uint16_t reversed_keys[4];
    for (int i = 0; i < 4; i++) {
        reversed_keys[i] = keys[3 - i];
    }
    return feistel_encrypt(block, reversed_keys);
}

// qsort 比较函数：按 count 降序排列
int cmp_diff(const void *a, const void *b) {
    diff_count_t *d1 = (diff_count_t *)a;
    diff_count_t *d2 = (diff_count_t *)b;
    return d2->count - d1->count;
}

// 统计相邻两个数的差值（绝对值）并记录各差值出现次数
// 参数：data 数组，n 数组长度，返回值为动态分配的 diff_count_t 数组，结果个数放入 *result_count
diff_count_t* calc_diff_stats(uint32_t *data, int n, int *result_count) {
    diff_count_t *diffs = malloc((n - 1) * sizeof(diff_count_t));
    if (!diffs) {
        fprintf(stderr, "申请 diffs 内存失败\n");
        exit(EXIT_FAILURE);
    }
    int count = 0;
    for (int i = 0; i < n - 1; i++) {
        uint32_t diff = (data[i+1] > data[i]) ? (data[i+1] - data[i]) : (data[i] - data[i+1]);
        int found = 0;
        // 查找是否已有该 diff 记录
        for (int j = 0; j < count; j++) {
            if (diffs[j].diff == diff) {
                diffs[j].count++;
                found = 1;
                break;
            }
        }
        if (!found) {
            diffs[count].diff = diff;
            diffs[count].count = 1;
            count++;
        }
    }
    *result_count = count;
    return diffs;
}

int main() {
    // 1. RDMA 初始化：获取设备列表，打开设备，分配保护域
    int num_devices = 0;
    struct ibv_device **dev_list = ibv_get_device_list(&num_devices);
    if (!dev_list || num_devices == 0) {
        fprintf(stderr, "没有找到 RDMA 设备\n");
        exit(EXIT_FAILURE);
    }
    struct ibv_context *context = ibv_open_device(dev_list[0]);
    if (!context) {
        fprintf(stderr, "打开设备失败\n");
        exit(EXIT_FAILURE);
    }
    struct ibv_pd *pd = ibv_alloc_pd(context);
    if (!pd) {
        fprintf(stderr, "分配保护域失败\n");
        exit(EXIT_FAILURE);
    }

    // 2. 循环申请 MR 并保存 rkey
    uint32_t *rkeys = malloc(NUM_MR * sizeof(uint32_t));
    if (!rkeys) {
        fprintf(stderr, "申请 rkeys 内存失败\n");
        exit(EXIT_FAILURE);
    }
    struct ibv_mr **mrs = malloc(NUM_MR * sizeof(struct ibv_mr *));
    if (!mrs) {
        fprintf(stderr, "申请 MR 指针数组失败\n");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < NUM_MR; i++) {
        // 为每个 MR 分配一块内存
        void *buf = malloc(MR_SIZE);
        if (!buf) {
            fprintf(stderr, "第 %d 个 MR 内存分配失败\n", i);
            exit(EXIT_FAILURE);
        }
        // 为了得到非0的 rkey，这里增加了远程读写权限
        mrs[i] = ibv_reg_mr(pd, buf, MR_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
        if (!mrs[i]) {
            fprintf(stderr, "第 %d 个 MR 注册失败\n", i);
            exit(EXIT_FAILURE);
        }
        rkeys[i] = mrs[i]->rkey;
    }

    // 3. 对所有 rkey 进行 Feistel 哈希变换
    uint32_t *hashes = malloc(NUM_MR * sizeof(uint32_t));
    if (!hashes) {
        fprintf(stderr, "申请 hashes 内存失败\n");
        exit(EXIT_FAILURE);
    }
    uint16_t feistel_keys[4] = {0x1234, 0x1234, 0x1234, 0x1234};
    for (int i = 0; i < NUM_MR; i++) {
        hashes[i] = feistel_encrypt(rkeys[i], feistel_keys);
    }

    // 4. 对哈希后的 rkey 计算相邻差值，并统计出现次数
    int hash_diff_count = 0;
    diff_count_t *hash_diffs = calc_diff_stats(hashes, NUM_MR, &hash_diff_count);
    qsort(hash_diffs, hash_diff_count, sizeof(diff_count_t), cmp_diff);

    // 5. 对原始 rkey 计算相邻差值，并统计出现次数
    int rkey_diff_count = 0;
    diff_count_t *rkey_diffs = calc_diff_stats(rkeys, NUM_MR, &rkey_diff_count);
    qsort(rkey_diffs, rkey_diff_count, sizeof(diff_count_t), cmp_diff);

    // 6. 将哈希差值统计结果输出到文件 output.txt
    FILE *fp_hash = fopen("output.txt", "w");
    if (!fp_hash) {
        fprintf(stderr, "打开 output.txt 文件失败\n");
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < hash_diff_count; i++) {
        fprintf(fp_hash, "%u: %d\n", hash_diffs[i].diff, hash_diffs[i].count);
    }
    fclose(fp_hash);
    printf("哈希差值统计结果已写入 output.txt\n");

    // 7. 将原始 rkey 差值统计结果输出到文件 rkey_diff.txt
    FILE *fp_rkey = fopen("rkey_diff.txt", "w");
    if (!fp_rkey) {
        fprintf(stderr, "打开 rkey_diff.txt 文件失败\n");
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < rkey_diff_count; i++) {
        fprintf(fp_rkey, "%u: %d\n", rkey_diffs[i].diff, rkey_diffs[i].count);
    }
    fclose(fp_rkey);
    printf("原始 rkey 差值统计结果已写入 rkey_diff.txt\n");

    // 8. 测试解密是否正确（任选其中一个 rkey 进行测试）
    uint32_t test_key = rkeys[0];
    uint32_t encrypted = feistel_encrypt(test_key, feistel_keys);
    uint32_t decrypted = feistel_decrypt(encrypted, feistel_keys);
    if (decrypted == test_key) {
        printf("解密验证成功！\n");
    } else {
        printf("解密验证失败！原始: %u, 解密后: %u\n", test_key, decrypted);
    }

    // 9. 清理资源：注销 MR、释放内存、销毁保护域和上下文
    for (int i = 0; i < NUM_MR; i++) {
        free(mrs[i]->addr);  // 释放缓冲区
        ibv_dereg_mr(mrs[i]);
    }
    free(mrs);
    free(rkeys);
    free(hashes);
    free(hash_diffs);
    free(rkey_diffs);

    ibv_dealloc_pd(pd);
    ibv_close_device(context);
    ibv_free_device_list(dev_list);

    return 0;
}

