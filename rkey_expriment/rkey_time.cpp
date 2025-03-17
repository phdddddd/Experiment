#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <assert.h>
//rkey混淆需要两次解析报文，加密解密
// 左循环移位，针对16位整数。width默认为16.
uint16_t rol(uint16_t x, int shift, int width) {
    return ((x << shift) & ((1 << width) - 1)) | (x >> (width - shift));
}

// 轮函数：F(x, k) = ROL(x,3) + k mod 2^16
uint16_t F(uint16_t x, uint16_t k) {
    return (rol(x, 3, 16) + k) & 0xFFFF;
}

// Feistel加密，block为32位数据，keys为轮密钥数组，rounds为轮数
uint32_t feistel_encrypt(uint32_t block, const uint16_t keys[], int rounds) {
    uint16_t L = (block >> 16) & 0xFFFF;
    uint16_t R = block & 0xFFFF;
    for (int i = 0; i < rounds; i++) {
        uint16_t temp = R;
        R = L ^ F(R, keys[i]);
        L = temp;
    }
    return ((uint32_t)L << 16) | R;
}

// Feistel解密，密钥顺序逆转
uint32_t feistel_decrypt(uint32_t cipher, const uint16_t keys[], int rounds) {
    uint16_t L = (cipher >> 16) & 0xFFFF;
    uint16_t R = cipher & 0xFFFF;
    for (int i = rounds - 1; i >= 0; i--) {
        uint16_t temp = L;
        L = R ^ F(L, keys[i]);
        R = temp;
    }
    return ((uint32_t)L << 16) | R;
}

// 计算两个timespec之间的时间差，结果单位为纳秒
long long timespec_diff_ns(struct timespec *start, struct timespec *end) {
    long long diff_sec = end->tv_sec - start->tv_sec;
    long long diff_ns = end->tv_nsec - start->tv_nsec;
    return diff_sec * 1000000000LL + diff_ns;
}

int main() {
    // 定义轮密钥和轮数
    const int rounds = 4;
    const uint16_t keys[rounds] = {0x1234, 0x1234, 0x1234, 0x1234};

    // 示例验证
    for (uint32_t i = 0; i < 10; i++) {
        uint32_t plaintext = i;  // 32位测试数据
        uint32_t ciphertext = feistel_encrypt(plaintext, keys, rounds);
        uint32_t decrypted = feistel_decrypt(ciphertext, keys, rounds);

        printf("明文      : 0x%08X\n", plaintext);
        printf("密文      : 0x%08X\n", ciphertext);
        printf("解密后明文: 0x%08X\n\n", decrypted);

        assert(plaintext == decrypted && "解密失败！");
    }

    // 统计大量数据上加密的平均延迟（纳秒）
    const unsigned long iterations = 10000000UL; // 例如1000万次加密
    struct timespec start, end;

    // 获取起始时间
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }

    for (unsigned long i = 0; i < iterations; i++) {
        // 使用volatile防止编译器优化掉计算
        volatile uint32_t dummy = feistel_encrypt(i, keys, rounds);
        (void)dummy;
    }

    // 获取结束时间
    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }

    long long total_time_ns = timespec_diff_ns(&start, &end);
    double avg_time_ns = (double)total_time_ns / iterations;

    printf("总共执行 %lu 次加密，耗时 %lld 纳秒\n", iterations, total_time_ns);
    printf("平均每次加密延迟: %.3f 纳秒\n", avg_time_ns);

    return 0;
}
