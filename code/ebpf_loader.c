#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>

int main(int argc, char **argv) {
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    struct bpf_object *obj;
    int ifindex, prog_fd;
    char filename[256];
    int err;

    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit");
        return 1;
    }
    
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
        return 1;
    }
    
    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }
    
    snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
    
    err = bpf_prog_load(filename, BPF_PROG_TYPE_XDP, &obj, &prog_fd);
    if (err) {
        fprintf(stderr, "Error loading BPF program: %s\n", strerror(-err));
        return 1;
    }
    
    err = bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST);
    if (err) {
        fprintf(stderr, "Error attaching XDP program: %s\n", strerror(-err));
        goto cleanup;
    }
    
    printf("eBPF program loaded successfully. Press Ctrl+C to unload.\n");
    
   
    pause();
    

    bpf_set_link_xdp_fd(ifindex, -1, 0);
    
cleanup:
    bpf_object__close(obj);
    return 0;
}