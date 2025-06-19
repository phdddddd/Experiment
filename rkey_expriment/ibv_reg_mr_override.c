#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>

/*
 * fexit 程序：拦截内核中处理用户 MR 注册的函数 ib_uverbs_cmd_reg_mr，
 * 并将其返回值修改为 0，模拟成功的结果。
 */
 libbpf_set_strict_mode(LIBBPF_STRICT_DISABLED);
SEC("fexit/ib_uverbs_reg_mr")
int fexit_ib_uverbs_cmd_reg_mr(struct pt_regs *ctx)
{
    bpf_override_return(ctx, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";


